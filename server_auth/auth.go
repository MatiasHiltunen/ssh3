package server_auth

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"runtime"
	"strings"

	"github.com/francoismichel/ssh3"
	"github.com/francoismichel/ssh3/util/unix_util"

	"github.com/rs/zerolog/log"
)

func HandleAuths(ctx context.Context, enablePasswordLogin bool, defaultMaxPacketSize uint64, handlerFunc ssh3.AuthenticatedHandlerFunc) (http.HandlerFunc, error) {
	if runtime.GOOS != "linux" && enablePasswordLogin {
		return nil, fmt.Errorf("password login not supported on %s/%s systems", runtime.GOOS, runtime.GOARCH)
	}
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		peerVersion, err := ssh3.ParseVersionString(r.UserAgent())
		log.Debug().Msgf("received request from User-Agent %s", r.UserAgent())
		log.Debug().Msgf("peer version: protocol version %s, software version %s", peerVersion.GetProtocolVersion(), peerVersion.GetSoftwareVersion())
		// currently apply strict version rules
		if err != nil {
			http.Error(w, "Unsupported SSH3 user-agent", http.StatusForbidden)
			return
		}
		if !ssh3.IsVersionSupported(peerVersion) {
			http.Error(w, fmt.Sprintf("Unsupported version: %s not supported by server with version %s", peerVersion.GetProtocolVersion(), ssh3.ThisVersion().GetProtocolVersion()), http.StatusForbidden)
			return
		}
		// Only call Flush() here, as calling flush prevents from adding the Content-Length header to the response
		// The Content-Length can be useful upon receiving an error response
		if flusher, ok := w.(http.Flusher); ok {
			defer flusher.Flush()
		}
		qconn, ok := ssh3.QUICConnectionFromRequest(r)
		if !ok {
			http.Error(w, "HTTP/3 connection unavailable", http.StatusInternalServerError)
			return
		}
		if !qconn.ConnectionState().TLS.HandshakeComplete {
			// do not process early data (0-RTT) when performing authorization
			// to avoid replay attacks
			w.WriteHeader(http.StatusTooEarly)
			return
		}
		conv, err := ssh3.NewServerConversation(qconn.Context(), nil, qconn, qconn, defaultMaxPacketSize, peerVersion)
		if err != nil {
			log.Error().Msgf("could not create new server conversation")
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		authenticated := false
		defer func() {
			if !authenticated {
				conv.Close()
			}
		}()
		completeAuth := func(username string, conv *ssh3.Conversation, w http.ResponseWriter, r *http.Request) {
			authenticated = true
			handlerFunc(username, conv, w, r)
		}

		convID := conv.ConversationID()
		base64ConvID := base64.StdEncoding.EncodeToString(convID[:])

		username := r.URL.User.Username()
		if username == "" {
			username = r.URL.Query().Get("user")
		}
		user, err := unix_util.GetUser(username)
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		identityVerifiers, err := GetAuthorizedIdentities(user)
		if err != nil {
			log.Error().Msgf("error in JWT auth handling when retrieving authorized identities: %s", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		// first, handle the HTTP request verifiers (often plugins)
		for _, abstractVerifier := range identityVerifiers {
			switch verifier := abstractVerifier.(type) {
			case *WrappedPluginVerifier:
				if verifier.Verify(r, base64ConvID) {
					log.Debug().Msgf("request for user %s successfully verified by plugin", username)
					completeAuth(username, conv, w, r)
					return
				}
			}
		}

		log.Debug().Msgf("no suitable plugin found to authenticate the request")

		authorization := r.Header.Get("Authorization")
		if enablePasswordLogin && strings.HasPrefix(authorization, "Basic ") {
			HandleBasicAuth(completeAuth, conv)(w, r)
		} else if strings.HasPrefix(authorization, "Bearer ") {
			HandleBearerAuth(username, base64ConvID, HandleJWTAuth(username, conv, identityVerifiers, completeAuth))(w, r)
		} else {
			w.WriteHeader(http.StatusUnauthorized)
		}
	}, nil
}

func HandleBasicAuth(handlerFunc ssh3.AuthenticatedHandlerFunc, conv *ssh3.Conversation) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		username, password, ok := r.BasicAuth()
		if !ok {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		ok, err := unix_util.UserPasswordAuthentication(username, password)
		if err != nil || !ok {
			if err != nil {
				log.Error().Msgf("user authentication failed: %s", err)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		handlerFunc(username, conv, w, r)
	}
}
