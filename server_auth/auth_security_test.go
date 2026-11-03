package server_auth

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func TestMalformedUserAgentIsForbidden(t *testing.T) {
	var calls atomic.Int32
	handler, err := HandleAuths(context.Background(), false, 30_000, func(string, *ssh3.Conversation, http.ResponseWriter, *http.Request) {
		calls.Add(1)
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, agent := range []string{"", "x", "ssh", "SSH 3.0", strings.Repeat("x", 500)} {
		r := httptest.NewRequest(http.MethodConnect, "https://localhost/", nil)
		r.Header.Set("User-Agent", agent)
		w := httptest.NewRecorder()
		handler(w, r)
		if w.Code != http.StatusForbidden {
			t.Fatalf("user agent %q: status %d", agent, w.Code)
		}
	}
	if calls.Load() != 0 {
		t.Fatal("malformed request reached authenticated handler")
	}
}

func testCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1"), net.ParseIP("::1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(cert)
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: private}, pool
}

func TestWildcardListenersRequireAuthentication(t *testing.T) {
	for _, bind := range []string{"0.0.0.0:0", "[::]:0"} {
		t.Run(bind, func(t *testing.T) {
			packet, err := net.ListenPacket("udp", bind)
			if err != nil {
				if bind == "[::]:0" {
					t.Skipf("IPv6 unavailable: %v", err)
				}
				t.Fatal(err)
			}
			defer packet.Close()
			certificate, pool := testCertificate(t)
			h3 := &http3.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{certificate}}, EnableDatagrams: true}
			var authenticated atomic.Int32
			server := ssh3.NewServer(30_000, 10, h3, func(string, *ssh3.Conversation) error {
				authenticated.Add(1)
				return nil
			})
			h3.Handler, err = HandleAuths(context.Background(), false, 30_000, server.GetHTTPHandlerFunc(context.Background()))
			if err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- server.Serve(packet) }()
			defer func() { _ = server.Close(); <-done }()
			port := packet.LocalAddr().(*net.UDPAddr).Port
			host := "127.0.0.1"
			if bind == "[::]:0" {
				host = "::1"
			}
			address := net.JoinHostPort(host, big.NewInt(int64(port)).String())
			transport := &http3.Transport{TLSClientConfig: &tls.Config{RootCAs: pool}, EnableDatagrams: true}
			defer transport.Close()
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			for _, tlsConfig := range []*tls.Config{
				{RootCAs: x509.NewCertPool()},
				{RootCAs: pool, ServerName: "wrong-host.example"},
			} {
				untrusted := &http3.Transport{TLSClientConfig: tlsConfig}
				req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address+"/", nil)
				if err != nil {
					t.Fatal(err)
				}
				if rsp, err := untrusted.RoundTrip(req); err == nil {
					rsp.Body.Close()
					t.Error("TLS accepted an untrusted certificate or incorrect hostname")
				}
				untrusted.Close()
			}
			for _, authorization := range []string{"", "Bearer invalid", "Basic dXNlcjpwYXNz"} {
				req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+address+"/?user=ssh3-nonexistent-security-test-user", nil)
				if err != nil {
					t.Fatal(err)
				}
				req.Proto = "ssh3"
				req.Header.Set("User-Agent", ssh3.GetCurrentVersionString())
				req.Header.Set("Authorization", authorization)
				rsp, err := transport.RoundTrip(req)
				if err != nil {
					t.Fatal(err)
				}
				_, _ = io.Copy(io.Discard, rsp.Body)
				_ = rsp.Body.Close()
				if rsp.StatusCode != http.StatusUnauthorized {
					t.Fatalf("unverified credentials returned HTTP %d", rsp.StatusCode)
				}
			}
			// A custom SSH3 stream also needs an authenticated CONNECT conversation.
			conn, err := quic.DialAddr(ctx, address, &tls.Config{RootCAs: pool, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true})
			if err != nil {
				t.Fatal(err)
			}
			defer conn.CloseWithError(0, "test complete")
			stream, err := conn.OpenStreamSync(ctx)
			if err != nil {
				t.Fatal(err)
			}
			_, _ = stream.Write(util.AppendVarInt(nil, ssh3.SSH_FRAME_TYPE))
			_ = stream.SetReadDeadline(time.Now().Add(5 * time.Second))
			_, err = stream.Read(make([]byte, 1))
			var streamError *quic.StreamError
			if !errors.As(err, &streamError) || streamError.ErrorCode != quic.StreamErrorCode(http3.ErrCodeRequestRejected) {
				t.Fatalf("unauthenticated SSH3 stream was not rejected: %v", err)
			}
			if authenticated.Load() != 0 {
				t.Fatal("unverified credentials reached conversation handler")
			}
		})
	}
}
