package ssh3_test

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/francoismichel/ssh3"
	serverpubkey "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/server"
	"github.com/francoismichel/ssh3/util"
	"github.com/golang-jwt/jwt/v5"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"golang.org/x/crypto/ssh"
)

// A nonzero control stream distinguishes SSH3's full stream IDs from RFC 9297's
// quarter IDs. Exercise both datagram directions with actual QUIC connections.
func TestAuthenticatedDatagramsKeepFullConversationStreamID(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2), NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		IPAddresses: []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:    x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AddCert(certificate)
	packet, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer packet.Close()
	h3 := &http3.Server{EnableDatagrams: true, TLSConfig: &tls.Config{Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: private}}}}
	result := make(chan error, 1)
	server := ssh3.NewServer(30_000, 10, h3, func(_ string, conversation *ssh3.Conversation) error {
		channel, err := conversation.AcceptChannel(conversation.Context())
		if err == nil && channel.ConversationStreamID() != 4 {
			err = fmt.Errorf("control stream ID = %d, want 4", channel.ConversationStreamID())
		}
		if err == nil {
			var payload []byte
			payload, err = channel.ReceiveDatagram(conversation.Context())
			if err == nil {
				err = channel.SendDatagram(payload)
			}
		}
		result <- err
		return err
	})
	authenticated := server.GetHTTPHandlerFunc(context.Background())
	sshPublic, err := ssh.NewPublicKey(public)
	if err != nil {
		t.Fatal(err)
	}
	verifier, err := serverpubkey.PubkeyAuthPlugin("test-user", string(ssh.MarshalAuthorizedKey(sshPublic)))
	if err != nil {
		t.Fatal(err)
	}
	h3.Handler = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		conn, ok := ssh3.QUICConnectionFromRequest(r)
		if !ok {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		conversation, err := ssh3.NewServerConversation(conn.Context(), nil, conn, conn, 30_000, ssh3.ThisVersion())
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		if !verifier.Verify(r, conversation.ConversationID().String()) {
			conversation.Close()
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		authenticated("test-user", conversation, w, r)
	})
	done := make(chan error, 1)
	go func() { done <- server.Serve(packet) }()
	defer func() { _ = server.Close(); <-done }()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	conn, err := quic.DialAddr(ctx, packet.LocalAddr().String(), &tls.Config{RootCAs: pool, NextProtos: []string{http3.NextProtoH3}}, &quic.Config{EnableDatagrams: true})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseWithError(0, "test complete")
	// Consume stream 0 with a rejected, unauthenticated channel before CONNECT.
	unauthenticated, err := conn.OpenStreamSync(ctx)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = unauthenticated.Write(util.AppendVarInt(nil, ssh3.SSH_FRAME_TYPE))
	_ = unauthenticated.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := unauthenticated.Read(make([]byte, 1)); err == nil {
		t.Fatal("unauthenticated channel was accepted")
	}
	state := conn.ConnectionState().TLS
	conversation, err := ssh3.NewClientConversation(30_000, 10, &state)
	if err != nil {
		t.Fatal(err)
	}
	defer conversation.Close()
	claims := jwt.MapClaims{
		"iss": "test-user", "sub": "ssh3", "aud": "unused", "client_id": "ssh3-test-user",
		"jti": conversation.ConversationID().String(), "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Minute).Unix(),
	}
	token, err := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims).SignedString(private)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodConnect, "https://"+packet.LocalAddr().String()+"/", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Proto = "ssh3"
	req.Header.Set("Authorization", "Bearer "+token)
	if err := conversation.EstablishClientConversation(req, &http3.Transport{EnableDatagrams: true}, conn, ssh3.AVAILABLE_CLIENT_VERSIONS); err != nil {
		t.Fatal(err)
	}
	channel, err := conversation.OpenUDPForwardingChannel(30_000, 10, nil, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1).To4(), Port: 1234})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("SSH3 datagram on control stream 4")
	if err := channel.SendDatagram(payload); err != nil {
		t.Fatal(err)
	}
	got, err := channel.ReceiveDatagram(ctx)
	if err != nil || !bytes.Equal(got, payload) {
		t.Fatalf("datagram round trip: %q, %v", got, err)
	}
	if err := <-result; err != nil {
		t.Fatal(err)
	}
}
