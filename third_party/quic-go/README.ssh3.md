# quic-go v0.64.1 compatibility patch

Source: <https://github.com/quic-go/quic-go/tree/v0.64.1>

Commit: `ed90516797ec8ed7314c2b163797eca58fd5a2b8`.
The upstream MIT license is in `LICENSE`. Non-test Go sources, `go.mod`, and
`go.sum` were copied from the checksum-verified module download. Upstream tests,
fixtures, generated mocks, and test utility directories are omitted. The root module still
requires v0.64.1 and uses a relative replacement pointing here.

The only source changes are the three HTTP/3 files shown in `ssh3.patch` (53 diff
lines). `UPSTREAM_FILES.json` records upstream and local SHA-256 hashes for all
203 copied files and the original Go module checksum.

SSH3's existing datagrams prefix the **full conversation stream ID**, whereas
RFC 9297 HTTP Datagrams use a quarter stream ID. Upstream HTTP/3 automatically
starts receiving QUIC datagrams when peer SETTINGS advertise datagram support.
That would race SSH3's receiver and change the wire format, particularly for
nonzero conversation IDs.

`RawClientConn.DisableDatagramHandling()` and
`RawServerConn.DisableDatagramHandling()` give SSH3 ownership of that receive loop.
They must be called before handling incoming unidirectional streams. They retain
the upstream SETTINGS parser, QUIC datagram negotiation checks, HTTP/3 control
stream validation, TLS verification, and authentication behavior. Other upstream
APIs retain their normal datagram handling by default.

The application uses the upstream raw connection APIs for stream routing. A real
QUIC regression verifies authenticated, bidirectional datagrams on conversation
stream 4, after rejecting an unauthenticated stream 0. Rust–Go UDP forwarding also
exercises the preserved framing.

When upgrading, reapply/reassess this patch against the new upstream release,
refresh the file manifest, and rerun tests and the independent upstream module
vulnerability scan described in `../../GO_VALIDATION.md`. A local replacement has
no registry version for govulncheck; the independent scan covers the upstream
version while the manifest and patch make the local changes reviewable.
