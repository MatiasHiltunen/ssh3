# Rust dependency update and validation

Validated on 2026-11-01 with Rust/Cargo 1.99.1 on Linux x86_64.
Base commit: `0021c06ddfc17bc72445383d2032ffbc080890be`.
Working branch: `chore/rust-dependency-upgrade`.

**Build and supported runtime checks pass. The dependency security audit still
reports two findings, so this is not a clean security certification.**

## Dependency changes

All 25 remaining direct registry dependencies use the latest non-yanked stable
versions returned by crates.io at validation time. Cargo.lock was regenerated
with the latest compatible transitive versions. Older major versions required
by dependencies can still appear in the lockfile.

| Dependency | Version |
| --- | --- |
| async-trait | 0.1.92 |
| base64 | 0.23.1 |
| bytes | 1.12.1 |
| clap | 4.6.7 |
| futures-util | 0.3.34 |
| h3 | 0.0.8 |
| h3-quinn | 0.0.10 |
| http | 1.5.0 |
| nix | 0.31.3 |
| p256 | 0.14.0 |
| quinn | 0.11.12 |
| rand | 0.10.3 |
| rcgen | 0.14.10 |
| reqwest | 0.13.5 |
| rsa | 0.9.10 |
| rustls | 0.23.46 |
| serde | 1.0.229 |
| serde_json | 1.0.154 |
| sha2 | 0.11.1 |
| signature | 3.0.0 |
| ssh-key | 0.6.7 |
| tempfile | 3.27.0 |
| tokio | 1.54.1 |
| url | 2.5.8 |
| webpki-roots | 1.0.11 |

Important transitive updates include quinn-proto 0.11.19, rustls-webpki 0.103.16,
and the active crypto-bigint backend at 0.7.10.

Reqwest now enables its `rustls` and, for the client, `form` features explicitly.
OIDC randomness uses Rand's fallible OS RNG. P-256 signing and verification use
the current signature/SEC1 APIs; RSA and SSH-key operations use their compatible
re-exported traits, digest, and test RNG instead of redundant direct dependencies.

The unmaintained rustls-pemfile dependency was replaced with rustls-pki-types'
PEM parser through Rustls' re-export. ECDSA SSH key parsing remains enabled, while
ssh-key's old P-256 cryptographic backend is disabled. Shared test support
generates fresh P-256 identities from OS entropy for each test; no private-key
fixtures are stored in the repository.

The existing vendored h3 0.0.8 patch is preserved: upstream is still at 0.0.8,
and the local patch supports SSH3's extended CONNECT protocol token.
Go source, dependencies, toolchain settings, and workflows are unchanged.

## Runtime and security hardening

- Race resolved addresses so an unreachable IPv6 address does not prevent a
  working IPv4 connection. Cryptographic handshake errors fail promptly and
  retain the certificate error instead of waiting for unreachable alternatives.
- Reject incoming SSH strings larger than 16 MiB before allocating their buffer
  in the synchronous codec, asynchronous channel reader, and QUIC setup reader.
  This is a new per-field resource limit; larger fields are now rejected.
- Reject JWT/OIDC tokens at their expiration instant (`exp <= now`).
- Use RSA signing blinding as defense in depth. This does **not** resolve the
  upstream RSA timing advisory.
- Remove non-looping loops and redundant expressions that prevented checks with
  the current Clippy toolchain.

## Validation results

| Check | Result |
| --- | --- |
| `cargo fmt --all -- --check` | Passed |
| `cargo check --workspace --all-targets --all-features --locked` | Passed |
| `cargo clippy --workspace --all-targets --locked` | Passed, with existing style warnings |
| `cargo build --workspace --release --locked` | Passed |
| Supported Rust tests | 78 passed; 0 failed |
| Release client/server: authenticated P-256 command | Passed; expected stdout and exit 0 |
| Release client/server: missing authentication | Rejected; exit 1 and no command output |
| Release client: untrusted self-signed certificate | Rejected with `UnknownIssuer`; exit 1 |

Tests exercise Ed25519/P-256/RSA authentication, mock OIDC including ES256 and
PKCE, token tampering and invalid claims, shell/exec/PTY/signals, trusted and
untrusted TLS, hostname verification, certificate file parsing, DNS fallback,
malicious lengths, HTTP/3 datagrams, and authenticated Rust-to-Rust TCP/UDP
forwarding. The CLI authentication smoke test used `--insecure` only against its
ephemeral loopback certificate; certificate rejection was checked separately.
Trusted-certificate connections are exercised throughout the Rust tests.

23 existing tests were filtered: 19 invoke Go binaries, outside the requested
Rust-only scope, and four require Unix-domain sockets, whose creation this
environment denies with `EPERM`. Those four are:

- `exec_capture_round_trips_with_ed25519_agent_auth`
- `exec_capture_round_trips_with_rsa_agent_auth`
- `forward_agent_exposes_remote_ssh_auth_sock_and_proxies_requests`
- `forward_agent_survives_multiple_remote_connections_in_one_session`

Reproduce this environment's test run with:

```sh
cargo test --workspace --all-targets --locked --no-fail-fast -- \
  --skip _against_the_go_server \
  --skip _against_the_real_go_server \
  --skip tests::real_go_client_ \
  --skip tests::go_client_ \
  --skip tests::go_agent_probe_ \
  --skip tests::exec_capture_round_trips_with_ed25519_agent_auth \
  --skip tests::exec_capture_round_trips_with_rsa_agent_auth \
  --skip tests::forward_agent_exposes_remote_ssh_auth_sock_and_proxies_requests \
  --skip tests::forward_agent_survives_multiple_remote_connections_in_one_session
```

On a host permitting Unix-domain sockets, omit the last four filters to test
agent authentication and forwarding too. Strict Clippy with `-D warnings` is
not clean because of existing style warnings in test code; vendored h3 also
emits compiler warnings. The CLI currently reports a generic `H3_NO_ERROR`
connection close for a rejected unauthenticated request.

## Dependency security findings

Cargo-audit 0.22.2 used RustSec database commit
`2295466c4e9df26647fd67d8fa1c705ac2fc7f81`, updated 2026-10-30.
The original lockfile produced **17 vulnerability findings** plus an unmaintained
PEM-parser warning. The updated lockfile produces **2 vulnerability findings**
and **no maintenance warnings**. No advisories are ignored or suppressed.

| Remaining finding | Assessment |
| --- | --- |
| [RUSTSEC-2023-0071](https://rustsec.org/advisories/RUSTSEC-2023-0071.html), rsa 0.9.10 | Active dependency; no patched upstream version exists. RSA private-key timing risk remains despite signing blinding. Prefer Ed25519 identities while this is unresolved. |
| [RUSTSEC-2026-0387](https://rustsec.org/advisories/RUSTSEC-2026-0387.html), crypto-bigint 0.5.5 | Retained in ssh-key's optional dependency resolution in Cargo.lock. Absent from the actual build dependency tree, including all workspace features and targets; the release ssh-key fingerprint has no P-256/P-384/P-521 backend dependencies. Active P-256 operations use crypto-bigint 0.7.10, above the patched threshold 0.7.6. |

Plain `cargo audit` intentionally still exits 1. Its complete output is saved in
[`validation/rustsec-audit.json`](validation/rustsec-audit.json); process-level
smoke results are in [`validation/cli-smoke.json`](validation/cli-smoke.json).

The updates address the lockfile's Quinn, Rustls, WebPKI, and trust-store
advisories. These checks cover the Rust implementation on Linux x86_64 and are
not a complete protocol or application security audit. The server's development
defaults bind to loopback and do not require authentication: use `--require-auth`
with authorized identities before exposing a listener, and configure trusted
certificates rather than using the client's `--insecure` option.
