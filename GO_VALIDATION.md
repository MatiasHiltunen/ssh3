# Go update and combined security validation

Validated locally on Linux x86_64 using Go 1.27.3, Rust/Cargo 1.99.1, and
govulncheck 1.9.0. Base: `95671a81207ec2593f11d4c19fefca4066c0a4e7`
(main, merged PR #1). This records the initial validation before PR #2 was published and merged.
The [CI regression follow-up](validation/GO_CI_REGRESSIONS.md) records the later
compatibility fixes and their validation.
Machine-readable results and dependency changes: [`validation/go-validation.json`](validation/go-validation.json).

## Changes

The Rust listener protection remains in place: unauthenticated development works
on IPv4/IPv6 loopback; other listeners require authentication or the explicitly
named insecure development override. Actual endpoints and direct connection
handlers are validated too. See [`validation/AUTHENTICATED_BIND.md`](validation/AUTHENTICATED_BIND.md).

The Go server already required authentication on every listener. That behavior is
preserved, including wildcard listeners; no insecure Go authentication bypass was
added. Go receives these fixes:

- Malformed or short User-Agent headers return HTTP 403 instead of panicking.
- SSH strings and peer packet sizes are bounded before allocation; data encoding
  avoids unsigned underflow and stays within the advertised packet size.
- Channel writes are serialized, short writes are reported, and reordered
  datagrams retain order with at most 128 pending channel queues.
- Authorized identity files are closed after every read; scanner failures reject
  authentication. This prevents repeated authentication from leaking descriptors.
- Linux password hashing protects libc's shared `crypt` buffer across concurrent
  requests and handles invalid hash results safely.
- The client waits for the completed TLS handshake before deriving conversation
  IDs/signatures. Server authorization still rejects early data. Successful CONNECT
  responses are flushed only after authentication.
- Unsafe logging of live QUIC internals is removed; agent-socket error paths clean
  up their contexts/listeners.

The module and CI use Go 1.27.3. Direct and indirect dependencies were updated and
`go mod tidy` run; `x/exp/slices` was replaced by standard-library `slices`.

| Component | Before | After |
| --- | --- | --- |
| Go | 1.21 | 1.27.3 |
| quic-go | v0.40.1 prerelease fork | v0.64.1 plus documented datagram shim |
| x/crypto | v0.17.0 | v0.58.0 |
| golang-jwt/jwt/v5 | v5.0.0 | v5.3.1 |
| coreos/go-oidc/v3 | v3.7.0 | v3.21.0 |
| certmagic | v0.20.0 | v0.25.6 |

The modern QUIC/HTTP3 APIs use raw connection routing. SSH3's existing full-stream-ID
datagram format is retained by a **53-line upstream diff across three HTTP/3 files**.
Upstream production sources are included under `third_party/quic-go`; its
[`README.ssh3.md`](third_party/quic-go/README.ssh3.md), license, exact patch, module
checksum, and file hash manifest make the local replacement reviewable. This adds
203 upstream files; most added source is unchanged upstream code.

The Rust `h3` directory moved unchanged from `vendor/h3` to `third_party/h3` so
ordinary Go commands no longer select an unrelated Rust directory as Go's vendor
tree. The Rust client retains HTTP/3 critical streams after CONNECT while handing
SSH3 channel streams to its own router. The old abort-and-drop behavior broke
connections against the updated Go server's correct control-stream validation.

Go library consumers must migrate to upstream's `*quic.Conn` / `*http3.Transport`
types, pass the connection to `EstablishClientConversation`, and serve through
`ssh3.Server.Serve` / `ListenAndServe`. CLI flags, TLS trust checks, authentication
methods, and the SSH3 wire format retain their behavior. Packet sizes outside
64 bytes–16 MiB are now rejected deliberately.

## Validation results

| Check | Result |
| --- | --- |
| `go test ./...` | Passed; 15 new test functions plus one fuzz target |
| `go test -race ./...` | Passed, no reported races |
| `go vet ./...` | Passed, no warnings; enabled in `make lint` |
| `go test -tags disable_password_auth ./...` | Passed |
| SSH-string fuzzing, 10 seconds, two workers | 235,539 inputs, no failures |
| `go mod verify` | All downloaded module checksums verified |
| Linux client and server builds | Passed, including password-enabled cgo server and cgo-free server |
| Cross builds | Passed: Darwin arm64 client, Linux 386 server, FreeBSD amd64 server |
| Available Rust workspace tests | **106 passed, 0 failed; seven filtered** |
| Go interoperability within the Rust suite | **16 passed**, including real Go CLI/server tests |
| Rust check, all targets/features, locked | Passed |
| Rust Clippy, all targets, locked | Passed with existing warnings |
| Rust formatting / Git whitespace | Passed |
| Earlier Rust process-level bind checks | 12 passed; results retained in `validation/bind-configuration.json` |

New Go regressions cover malformed headers; IPv4/IPv6 wildcard authentication;
rejection of unauthenticated custom streams; certificate trust and hostname
failures; JWT user, audience, expiry, algorithm, signature, and TLS-conversation
binding; allocation/packet limits; concurrent writes/hashing; and identity-file
descriptor cleanup. A trusted-certificate QUIC test authenticates conversation
**stream 4** and round-trips datagrams both ways, catching quarter-ID regressions
that conversation stream 0 would hide.

The combined Rust run covers Ed25519, RSA, P-256, OIDC, password auth, exec,
PTY/shell, resize/signals, TCP forwarding, and UDP forwarding in both language
directions where supported. The Linux Go-server fixtures now temporarily install
their test identities in the account database's actual home and restore the exact
previous contents on drop. The Go interop helper drains command pipes before
`Wait`, preventing lost output/exit status under load.

## Security scan and limits

Before the Go dependency update, govulncheck reported **57 module advisories,
13 with reachable symbol traces**. After the update it reports **zero reachable
advisories** and one module-only advisory, [GO-2026-5932](https://pkg.go.dev/vuln/GO-2026-5932),
for unmaintained OpenPGP packages in stable x/crypto v0.58.0. SSH3 does not import
those affected packages. The latest stable version is retained rather than
selecting an unreleased commit solely to remove unused OpenPGP code.

A local module replacement has no registry version for govulncheck. Therefore a
separate module scan uses the same dependency versions **without** the quic-go
replacement. It reports no advisory for upstream v0.64.1; the only module finding
is the same unused OpenPGP advisory. File hashes confirm all copied production
sources match upstream except the three documented shim files. Neither scan
suppresses advisories.

These results do not eliminate the existing Rust dependency findings:
[RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html) remains in
the active RSA dependency, and crypto-bigint 0.5.5 is a lockfile-only/unbuilt
finding. See [`RUST_VALIDATION.md`](RUST_VALIDATION.md). There is no claim of a
complete security audit or absence of all vulnerabilities; no Daybreak/Cloud scan
was run as part of this local validation.

Seven existing Rust agent tests require Unix-domain sockets, which this sandbox
rejects with `EPERM`. The legacy Go integration suite ran one of 18 specs; the
other 17 require opt-in server/account/credential fixtures that were unavailable.
They are not counted as passes. Real Go interoperability is covered separately
by the 16 Rust tests above. Cross-built binaries were not executed on other OSes.

Reproduce the supported Rust run with Go on `PATH`:

```sh
cargo test --workspace --all-targets --locked --no-fail-fast -- \
  --skip tests::exec_capture_round_trips_with_ed25519_agent_auth \
  --skip tests::exec_capture_round_trips_with_rsa_agent_auth \
  --skip tests::forward_agent_exposes_remote_ssh_auth_sock_and_proxies_requests \
  --skip tests::forward_agent_survives_multiple_remote_connections_in_one_session \
  --skip tests::rust_client_forward_agent_round_trips_against_the_real_go_server \
  --skip tests::go_agent_probe_talks_to_mock_agent_locally \
  --skip tests::real_go_client_forward_agent_round_trips_against_the_rust_server
```

Omit those filters on a host allowing Unix-domain sockets. Official toolchain
and transport sources: [Go downloads](https://go.dev/dl/),
[quic-go v0.64.1](https://github.com/quic-go/quic-go/releases/tag/v0.64.1).
