package server_pubkey_authentication

import (
	"crypto/ed25519"
	"crypto/rand"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func TestPublicKeyTokensRemainBoundToUserAndConversation(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, attacker, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	verifier := &PubkeyJWTIdentityVerifier{username: "test-user", pubkey: public}
	for _, name := range []string{"valid", "wrong-issuer", "wrong-subject", "wrong-audience", "wrong-client", "wrong-conversation", "expired", "missing-expiry", "future-issued-at", "wrong-key", "unsigned", "hmac"} {
		t.Run(name, func(t *testing.T) {
			claims := jwt.MapClaims{
				"iss": "test-user", "sub": "ssh3", "aud": "unused", "client_id": "ssh3-test-user",
				"jti": "tls-conversation-id", "iat": time.Now().Add(-time.Minute).Unix(), "exp": time.Now().Add(time.Minute).Unix(),
			}
			method := jwt.SigningMethod(jwt.SigningMethodEdDSA)
			key := any(private)
			switch name {
			case "wrong-issuer":
				claims["iss"] = "another-user"
			case "wrong-subject":
				claims["sub"] = "another-service"
			case "wrong-audience":
				claims["aud"] = "another-audience"
			case "wrong-client":
				claims["client_id"] = "ssh3-another-user"
			case "wrong-conversation":
				claims["jti"] = "another-tls-connection"
			case "expired":
				claims["exp"] = time.Now().Add(-time.Minute).Unix()
			case "missing-expiry":
				delete(claims, "exp")
			case "future-issued-at":
				claims["iat"] = time.Now().Add(time.Hour).Unix()
			case "wrong-key":
				key = attacker
			case "unsigned":
				method, key = jwt.SigningMethodNone, jwt.UnsafeAllowNoneSignatureType
			case "hmac":
				method, key = jwt.SigningMethodHS256, []byte(public)
			}
			token, err := jwt.NewWithClaims(method, claims).SignedString(key)
			if err != nil {
				t.Fatal(err)
			}
			req := httptest.NewRequest("CONNECT", "https://localhost/", nil)
			req.Header.Set("Authorization", "Bearer "+token)
			if got := verifier.Verify(req, "tls-conversation-id"); got != (name == "valid") {
				t.Fatalf("verification returned %v", got)
			}
		})
	}
}
