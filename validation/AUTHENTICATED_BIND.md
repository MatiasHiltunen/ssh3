# Authenticated listener configuration

Validated on 2026-11-03 with Rust/Cargo 1.99.1, Linux x86_64.
Base: `95671a81207ec2593f11d4c19fefca4066c0a4e7` (`main`, merged PR #1).

The follow-up Go update is validated in [`../GO_VALIDATION.md`](../GO_VALIDATION.md).
The combined revision now passes **106 Rust tests**, including 16 Go interoperability
tests; seven Unix-socket tests remain unavailable. The initial Rust-only run is
retained below as validation history.

## Behavior

An unauthenticated server can use IPv4 loopback (`127.0.0.0/8`), IPv6 loopback
(`::1`), or IPv4-mapped loopback. All other addresses, including private/link-local
addresses and the `0.0.0.0`/`::` wildcards, require authentication or the explicit
`--allow-insecure-unauthenticated-remote` development override. IPv4-compatible
IPv6 addresses such as `::127.0.0.1` are not treated as loopback.

The override is `ServerConfig::allow_insecure_unauthenticated_remote` in library
code and defaults to `false`. An unauthenticated external endpoint emits a warning
when the override is deliberately selected. Configured authentication remains
mandatory even when the override flag is present.

Authentication uses the existing `should_authenticate()` policy: `--require-auth`
enforces per-user identity lookup, a nonempty authorized-identity path list enables
identity authentication, and enabled password login requires an available platform
backend or a custom verifier. Providing a verifier without enabling password login
does not count as an enabled method. Identity files continue to be resolved for
the requested user at authentication time; missing credentials never enable an
unauthenticated fallback.

The shared library validation protects all public entry points:

- `run_with_self_signed()` rejects an unsafe configuration before certificate
  generation or socket binding.
- `serve_endpoint()` also validates `Endpoint::local_addr()`, so a caller cannot
  hide a wildcard listener behind a default loopback `ServerConfig`.
- `serve_connection()` also checks the peer address and, when available, the
  actual local destination IP before accepting an SSH3 conversation. On platforms
  lacking local-IP metadata, an unauthenticated peer must still be loopback.

The default loopback configuration and the existing authentication methods retain
their behavior. The original Rust listener commit left TLS trust, the wire protocol, Cargo
dependencies, Go implementation, and workflows unchanged. The follow-up Go update
includes the transport/API migration and Rust HTTP/3 lifecycle compatibility fix
documented in `GO_VALIDATION.md`. Workspace users constructing configs
with `..ServerConfig::default()` keep working. Downstream exhaustive struct literals
must include the new boolean field, normally set to `false`.

## Initial Rust-only checks

| Check | Result |
| --- | --- |
| Rust server library + CLI tests | 25 passed (included in workspace total) |
| Supported workspace Rust tests | 90 passed, 0 failed; includes 12 new regressions |
| `cargo check --workspace --all-targets --all-features --locked` | Passed |
| `cargo clippy --workspace --all-targets --locked` | Passed with existing warnings |
| `cargo build --workspace --bins --locked` | Passed |
| `cargo fmt --all -- --check` | Passed |
| Process-level CLI checks | 12 passed |
| `git diff --check` | Passed |

Rust regressions cover IPv4/IPv6 loopback, mapped IPv4, wildcard and nonlocal
addresses, configuration validation before binding, actual endpoint/config
mismatches, direct-connection address checks (including absent local-IP metadata),
identity and password authentication, missing-auth rejection, and the explicit
development override. Both IPv4 and IPv6 loopback/wildcard endpoints were exercised
with real QUIC/HTTP3 connections and trusted test certificates. Existing tests for
TLS certificate/hostname rejection, OIDC, signing methods, terminal sessions, and
TCP/UDP forwarding also passed.

The CLI checks use temporary OS-generated SSH identities. They confirm early
rejection of four unauthenticated external bind configurations, successful
unauthenticated commands over IPv4/IPv6 loopback, successful authenticated commands
on IPv4/IPv6 wildcards, and missing-auth rejection. They also confirm that
`--authorized-identity` alone still enables authentication. CLI connections used
`--insecure` only for ephemeral self-signed test certificates; trusted-certificate
and certificate-rejection behavior was checked by the Rust suite. Detailed CLI
results are in [`bind-configuration.json`](bind-configuration.json).

23 pre-existing tests were filtered: 19 require an unavailable Go executable, and
four require Unix-domain socket creation, which this environment rejects with
`EPERM`. No test definitions were disabled or removed. IPv6 was available and its
tests ran. Reproduce the supported workspace run with:

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

On a host with Go and Unix-domain socket support, omit the corresponding filters.
This change does not resolve the dependency advisories documented in the earlier
[`RUST_VALIDATION.md`](../RUST_VALIDATION.md).
