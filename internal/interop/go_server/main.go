package main

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	ssh3 "github.com/francoismichel/ssh3"
	_ "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/server"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/server_auth"
	"github.com/francoismichel/ssh3/util"
	"github.com/francoismichel/ssh3/util/unix_util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

const defaultURLPath = "/ssh3-term"

func main() {
	os.Exit(run())
}

func run() int {
	var bindAddr string
	var urlPath string
	var username string
	var authorizedIdentityPath string
	var certPath string
	var keyPath string

	flag.StringVar(&bindAddr, "bind", "127.0.0.1:4433", "UDP bind address")
	flag.StringVar(&urlPath, "url-path", defaultURLPath, "SSH3 URL path")
	flag.StringVar(&username, "user", "", "session username")
	flag.StringVar(&authorizedIdentityPath, "authorized-identity", "", "authorized identities file")
	flag.StringVar(&certPath, "cert", "", "certificate path")
	flag.StringVar(&keyPath, "key", "", "private key path")
	flag.Parse()

	if username == "" || authorizedIdentityPath == "" || certPath == "" || keyPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags: --user, --authorized-identity, --cert, and --key")
		return 2
	}

	util.ConfigureLogger("error")

	if err := ensureCertificate(certPath, keyPath); err != nil {
		fmt.Fprintf(os.Stderr, "could not prepare certificate: %s\n", err)
		return 1
	}

	certificate, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not load certificate: %s\n", err)
		return 1
	}

	baseTLSConfig := &tls.Config{
		Certificates: []tls.Certificate{certificate},
	}
	server := http3.Server{
		EnableDatagrams: true,
		QuicConfig: &quic.Config{
			Allow0RTT: true,
		},
		TLSConfig: http3.ConfigureTLSConfig(baseTLSConfig),
	}

	ssh3Server := ssh3.NewServer(30_000, 10, &server, func(authenticatedUsername string, conv *ssh3.Conversation) error {
		return handleConversation(authenticatedUsername, conv)
	})
	authenticatedHandler := ssh3Server.GetHTTPHandlerFunc(context.Background())

	mux := http.NewServeMux()
	mux.HandleFunc(urlPath, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", ssh3.GetCurrentVersionString())
		defer w.(http.Flusher).Flush()

		peerVersion, err := ssh3.ParseVersionString(r.UserAgent())
		if err != nil {
			fmt.Fprintf(os.Stderr, "unauthorized/forbidden: bad user-agent %q: %s\n", r.UserAgent(), err)
			http.Error(w, "unsupported SSH3 user-agent", http.StatusForbidden)
			return
		}
		if !ssh3.IsVersionSupported(peerVersion) {
			fmt.Fprintf(os.Stderr, "unauthorized/forbidden: unsupported version %q\n", r.UserAgent())
			http.Error(w, "unsupported SSH3 version", http.StatusForbidden)
			return
		}

		hijacker, ok := w.(http3.Hijacker)
		if !ok {
			http.Error(w, "http3 hijacker unavailable", http.StatusInternalServerError)
			return
		}

		streamCreator := hijacker.StreamCreator()
		qconn := streamCreator.(quic.Connection)
		if !qconn.ConnectionState().TLS.HandshakeComplete {
			fmt.Fprintln(os.Stderr, "unauthorized: TLS handshake incomplete")
			w.WriteHeader(http.StatusTooEarly)
			return
		}

		streamer, ok := r.Body.(http3.HTTPStreamer)
		if !ok {
			http.Error(w, "http3 stream unavailable", http.StatusInternalServerError)
			return
		}
		conv, err := ssh3.NewServerConversation(
			context.Background(),
			streamer.HTTPStream(),
			qconn,
			qconn,
			30_000,
			peerVersion,
		)
		if err != nil {
			fmt.Fprintf(os.Stderr, "unauthorized: could not create conversation: %s\n", err)
			http.Error(w, "could not create SSH3 conversation", http.StatusInternalServerError)
			return
		}

		requestedUsername := requestUsername(r, username)
		if requestedUsername == "" {
			fmt.Fprintln(os.Stderr, "unauthorized: missing username")
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		sessionUser := currentSessionUser(requestedUsername)

		identities, err := loadAuthorizedIdentities(sessionUser, authorizedIdentityPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "could not load authorized identities: %s\n", err)
			w.WriteHeader(http.StatusUnauthorized)
			return
		}

		conversationID := conv.ConversationID()
		base64ConversationID := base64.StdEncoding.EncodeToString(conversationID[:])
		for _, identity := range identities {
			if identity.Verify(r, base64ConversationID) {
				authenticatedHandler(requestedUsername, conv, w, r)
				return
			}
		}

		bearerToken, ok := server_auth.ParseBearerAuth(r.Header.Get("Authorization"))
		if ok {
			for _, identity := range identities {
				if identity.Verify(util.JWTTokenString{Token: bearerToken}, base64ConversationID) {
					authenticatedHandler(requestedUsername, conv, w, r)
					return
				}
			}
		}

		fmt.Fprintf(
			os.Stderr,
			"unauthorized: user=%s identities=%d authorization_present=%t\n",
			requestedUsername,
			len(identities),
			r.Header.Get("Authorization") != "",
		)
		w.WriteHeader(http.StatusUnauthorized)
	})
	server.Handler = mux

	packetConn, err := net.ListenPacket("udp", bindAddr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not bind %s: %s\n", bindAddr, err)
		return 1
	}
	defer packetConn.Close()

	fmt.Printf("READY %s\n", packetConn.LocalAddr().String())
	if err := server.Serve(packetConn); err != nil && !errors.Is(err, http.ErrServerClosed) {
		fmt.Fprintf(os.Stderr, "go interop server failed: %s\n", err)
		return 1
	}
	return 0
}

func requestUsername(r *http.Request, fallback string) string {
	if username := r.Header.Get("x-ssh3-user"); strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username)
	}
	if username := r.URL.User.Username(); username != "" {
		return username
	}
	if username := r.URL.Query().Get("user"); strings.TrimSpace(username) != "" {
		return strings.TrimSpace(username)
	}
	return fallback
}

func loadAuthorizedIdentities(
	user *unix_util.User,
	path string,
) ([]server_auth.IdentityVerifier, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return server_auth.ParseAuthorizedIdentitiesFile(user, file)
}

func ensureCertificate(certPath, keyPath string) error {
	certExists := fileExists(certPath)
	keyExists := fileExists(keyPath)
	if certExists && keyExists {
		return nil
	}
	if certExists != keyExists {
		return fmt.Errorf("certificate and key must either both exist or both be absent")
	}

	if err := os.MkdirAll(filepath.Dir(certPath), 0o755); err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(keyPath), 0o755); err != nil {
		return err
	}

	pubkey, privkey, err := util.GenerateKey()
	if err != nil {
		return err
	}
	cert, err := util.GenerateCert(privkey)
	if err != nil {
		return err
	}
	cert.DNSNames = append(cert.DNSNames, "localhost")
	if ip := net.ParseIP("127.0.0.1"); ip != nil {
		cert.IPAddresses = append(cert.IPAddresses, ip)
	}
	return util.DumpCertAndKeyToFiles(cert, pubkey, privkey, certPath, keyPath)
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

func handleConversation(authenticatedUsername string, conv *ssh3.Conversation) error {
	sessionUser := currentSessionUser(authenticatedUsername)

	for {
		channel, err := conv.AcceptChannel(conv.Context())
		if err != nil {
			return err
		}
		go handleChannel(sessionUser, channel)
	}
}

func currentSessionUser(username string) *unix_util.User {
	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		homeDir = os.Getenv("HOME")
	}
	shell := os.Getenv("SHELL")
	if shell == "" {
		shell = "/bin/sh"
	}
	return &unix_util.User{
		Username: username,
		Uid:      uint64(os.Getuid()),
		Gid:      uint64(os.Getgid()),
		Dir:      homeDir,
		Shell:    shell,
	}
}

func handleChannel(user *unix_util.User, channel ssh3.Channel) {
	genericMessage, err := channel.NextMessage()
	if err != nil || genericMessage == nil {
		return
	}

	requestMessage, ok := genericMessage.(*ssh3Messages.ChannelRequestMessage)
	if !ok {
		_ = writeStderr(channel, "expected a channel request\n")
		return
	}
	execRequest, ok := requestMessage.ChannelRequest.(*ssh3Messages.ExecRequest)
	if !ok {
		if requestMessage.WantReply {
			_ = channel.SendRequestFailure()
		}
		_ = writeStderr(channel, "unsupported request\n")
		return
	}
	if requestMessage.WantReply {
		if err := channel.SendRequestSuccess(); err != nil {
			_ = writeStderr(channel, fmt.Sprintf("could not send request reply: %s\n", err))
			return
		}
	}

	if err := runExec(user, channel, execRequest.Command); err != nil {
		_ = writeStderr(channel, fmt.Sprintf("%s\n", err))
	}
}

func runExec(user *unix_util.User, channel ssh3.Channel, command string) error {
	shell := user.Shell
	if shell == "" {
		shell = "/bin/sh"
	}

	cmd := exec.Command(shell, "-c", command)
	cmd.Dir = user.Dir
	cmd.Env = append(os.Environ(),
		fmt.Sprintf("HOME=%s", user.Dir),
		fmt.Sprintf("USER=%s", user.Username),
		fmt.Sprintf("LOGNAME=%s", user.Username),
		fmt.Sprintf("SHELL=%s", shell),
		"PATH=/usr/bin:/bin:/usr/sbin:/sbin",
	)

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	_ = stdin.Close()

	readResult := func(reader io.Reader, dataType ssh3Messages.SSHDataType) <-chan error {
		done := make(chan error, 1)
		go func() {
			done <- pumpOutput(channel, reader, dataType)
			close(done)
		}()
		return done
	}
	stdoutDone := readResult(stdout, ssh3Messages.SSH_EXTENDED_DATA_NONE)
	stderrDone := readResult(stderr, ssh3Messages.SSH_EXTENDED_DATA_STDERR)

	exitStatus := 1
	waitErr := cmd.Wait()
	if waitErr == nil {
		if status := cmd.ProcessState.ExitCode(); status >= 0 {
			exitStatus = status
		}
	} else if exitErr, ok := waitErr.(*exec.ExitError); ok {
		if status := exitErr.ExitCode(); status >= 0 {
			exitStatus = status
		}
	} else {
		return waitErr
	}

	if err := <-stdoutDone; err != nil {
		return err
	}
	if err := <-stderrDone; err != nil {
		return err
	}

	return channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
		WantReply: false,
		ChannelRequest: &ssh3Messages.ExitStatusRequest{
			ExitStatus: uint64(exitStatus),
		},
	})
}

func pumpOutput(channel ssh3.Channel, reader io.Reader, dataType ssh3Messages.SSHDataType) error {
	buf := make([]byte, int(channel.MaxPacketSize()))
	for {
		n, err := reader.Read(buf)
		if n > 0 {
			if _, writeErr := channel.WriteData(buf[:n], dataType); writeErr != nil {
				return writeErr
			}
		}
		if err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

func writeStderr(channel ssh3.Channel, message string) error {
	_, err := channel.WriteData([]byte(message), ssh3Messages.SSH_EXTENDED_DATA_STDERR)
	return err
}
