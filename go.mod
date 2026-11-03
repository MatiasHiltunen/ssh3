module github.com/francoismichel/ssh3

require (
	github.com/caddyserver/certmagic v0.25.6
	github.com/coreos/go-oidc/v3 v3.21.0
	github.com/creack/pty v1.1.24
	github.com/golang-jwt/jwt/v5 v5.3.1
	github.com/kevinburke/ssh_config v1.6.0
	github.com/onsi/ginkgo/v2 v2.34.0
	github.com/onsi/gomega v1.40.0
	github.com/quic-go/quic-go v0.64.1
	github.com/rs/zerolog v1.35.1
	go.uber.org/zap v1.28.0
	golang.org/x/crypto v0.58.0
	golang.org/x/oauth2 v0.37.0
	golang.org/x/term v0.47.0
)

require (
	github.com/Masterminds/semver/v3 v3.4.0 // indirect
	github.com/caddyserver/zerossl v0.1.6 // indirect
	github.com/go-jose/go-jose/v4 v4.1.8 // indirect
	github.com/go-logr/logr v1.4.3 // indirect
	github.com/go-task/slim-sprig/v3 v3.0.0 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/google/pprof v0.0.0-20261102214848-0031fcd306b0 // indirect
	github.com/klauspost/cpuid/v2 v2.4.1 // indirect
	github.com/libdns/libdns v1.1.1 // indirect
	github.com/mattn/go-colorable v0.1.16 // indirect
	github.com/mattn/go-isatty v0.0.24 // indirect
	github.com/mholt/acmez/v3 v3.1.7 // indirect
	github.com/miekg/dns v1.1.73 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/zeebo/blake3 v0.2.4 // indirect
	go.uber.org/multierr v1.11.0 // indirect
	go.uber.org/zap/exp v0.3.0 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	golang.org/x/mod v0.42.0 // indirect
	golang.org/x/net v0.62.0 // indirect
	golang.org/x/sync v0.24.0 // indirect
	golang.org/x/sys v0.49.0 // indirect
	golang.org/x/text v0.43.0 // indirect
	golang.org/x/tools v0.52.0 // indirect
	google.golang.org/protobuf v1.36.12 // indirect
)

go 1.27.3

replace github.com/quic-go/quic-go => ./third_party/quic-go
