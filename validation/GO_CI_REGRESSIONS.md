# Go CI regression fixes — 2026-11-03

Base: `a371e09ca217bf5c1685e24420d7ab5e545d1aa3`, the merge of PR #2.
The initial Linux CI run failed nine of 18 integration cases. The macOS amd64
job also timed out starting its CLI test on an arm64 runner.

## Changes

- Start QUIC connections through proxy jump with 1200-byte packets and disable
  inner path-MTU discovery. The newer transport's 1280-byte default does not
  initially fit within the outer QUIC/SSH3 datagram framing.
- Drop individual oversized UDP packets, including MTU probes, in both
  forwarding directions and continue receiving subsequent packets.
- Keep receiving after a datagram is queued for a channel not yet registered.
- Allow supported SSH3 0.1.5 servers to negotiate CONNECT without advertising
  the newer HTTP/3 setting. HTTP/3 SETTINGS parsing, TLS verification, JWT
  authentication, conversation binding, and version negotiation remain active.
- Pass bare `::1` to `net.JoinHostPort` to avoid double IPv6 brackets. Probe IPv6
  with an actual loopback bind rather than requiring interface-enumeration rights.
- Close test sockets and wait for child processes on every exit path. Use full
  reads for TCP payloads and readiness checks for UDP listeners. Preserve and
  restore pre-existing test profile/identity files.
- Drain stdout and stderr before `exec.Cmd.Wait` closes their pipes. Remove the
  unused preliminary pipes that leaked descriptors during command setup.
- Use a bounded five-second asynchronous test timeout, run macOS tests for the
  runner's actual Go host architecture, and make build targets phony so the
  existing `client` directory cannot silently suppress client compilation.

Two new integration cases check that oversized packets in either direction do
not break UDP forwarding, and that 12 short commands retain both stdout and
stderr before their exit status. The enabled suite now contains **20 cases**;
the existing legacy-server cases remain enabled in CI.

## Local validation

| Check | Result |
| --- | --- |
| Enabled integration suite, excluding legacy exec | **18 passed, 0 failed**, twice with the reported CI seed |
| IPv4/IPv6 forwarding and proxy jump | Passed, included above |
| Oversized datagram recovery | Passed in both directions |
| Fast-command stdout/stderr | Passed for 12 commands per integration run |
| `go test -race ./...` | Passed |
| `go vet ./...` | Passed |
| `go test -tags disable_password_auth ./...` | Passed |
| `make client server` on Linux | Both binaries built |
| Darwin amd64 and arm64 cross builds | Both client and server built for each architecture |
| Rust workspace, supported tests | **106 passed**, seven Unix-socket agent tests filtered |
| govulncheck | Zero reachable Go advisories; the existing unused OpenPGP module finding remains |
| Fixture cleanup | Original identity/profile contents restored byte-for-byte |

The sandbox maps only UID/GID 0 and cannot perform the `setgroups` call made by
the unmodified old servers before launching their command. Both real 0.1.5 servers
complete version negotiation and authenticated HTTP 200 locally, then fail exec
with `EPERM`. Their **two full exec cases require the normal Linux CI runner**
and are not counted as local passes. Native macOS execution also requires CI;
the local Darwin checks were cross builds.

Reproduce the local integration selection with the required account/key/cert
fixtures configured:

```sh
SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED=1 \
  go test ./integration_tests -count=1 \
    -ginkgo.skip='old supported server' -ginkgo.seed=1793665053
```

On the Linux CI runner, run `make integration-tests` without the skip filter to
exercise all 20 cases. This report records local validation before that CI run.
Structured results: [`go-ci-regressions.json`](go-ci-regressions.json).
