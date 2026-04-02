package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"net"
	"net/url"
	"os"
	"strings"
	"time"

	client_pubkey_authentication "github.com/francoismichel/ssh3/auth/plugins/pubkey_authentication/client"
	"github.com/francoismichel/ssh3/client"
	client_config "github.com/francoismichel/ssh3/client/config"
	ssh3Messages "github.com/francoismichel/ssh3/message"
	"github.com/francoismichel/ssh3/util"
	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
)

func main() {
	os.Exit(run())
}

func run() int {
	var rawURL string
	var username string
	var privateKeyPath string
	var serverName string
	var insecure bool

	flag.StringVar(&rawURL, "url", "", "server URL")
	flag.StringVar(&username, "user", "", "username")
	flag.StringVar(&privateKeyPath, "privkey", "", "private key path")
	flag.StringVar(&serverName, "server-name", "", "TLS server name override")
	flag.BoolVar(&insecure, "insecure", false, "skip certificate verification")
	flag.Parse()

	if rawURL == "" || username == "" || privateKeyPath == "" {
		fmt.Fprintln(os.Stderr, "missing required flags: --url, --user, and --privkey")
		return 2
	}

	util.ConfigureLogger("error")

	parsedURL, err := url.Parse(rawURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "invalid URL: %s\n", err)
		return 1
	}

	port := 443
	if parsedURL.Port() != "" {
		fmt.Sscanf(parsedURL.Port(), "%d", &port)
	}
	host := parsedURL.Hostname()
	if host == "" {
		fmt.Fprintln(os.Stderr, "URL must include a host")
		return 1
	}

	option, err := (&client_pubkey_authentication.PrivkeyOptionParser{}).Parse([]string{privateKeyPath})
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse private key option: %s\n", err)
		return 1
	}
	config, err := client_config.NewConfig(
		username,
		host,
		port,
		parsedURL.EscapedPath(),
		nil,
		map[client_config.OptionName]client_config.Option{
			client_pubkey_authentication.PRIVKEY_OPTION_NAME: option,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not build client config: %s\n", err)
		return 1
	}

	remoteAddr, err := net.ResolveUDPAddr("udp", config.URLHostnamePort())
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not resolve remote address: %s\n", err)
		return 1
	}
	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not create UDP socket: %s\n", err)
		return 1
	}
	defer udpConn.Close()

	tlsConfig := &tls.Config{
		InsecureSkipVerify: insecure,
		NextProtos:         []string{http3.NextProtoH3},
		ServerName:         host,
	}
	if serverName != "" {
		tlsConfig.ServerName = serverName
	}

	qconn, err := quic.DialEarly(
		context.Background(),
		udpConn,
		remoteAddr,
		tlsConfig,
		&quic.Config{
			Allow0RTT:          true,
			EnableDatagrams:    true,
			KeepAlivePeriod:    time.Second,
			MaxIncomingStreams: 10,
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not establish QUIC connection: %s\n", err)
		return 1
	}
	defer qconn.CloseWithError(0, "done")

	roundTripper := &http3.RoundTripper{
		EnableDatagrams: true,
	}
	defer roundTripper.Close()

	sshClient, err := client.Dial(context.Background(), config, qconn, roundTripper, nil)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not establish SSH3 conversation: %s\n", err)
		return 1
	}
	defer sshClient.Close()

	stdout, stderr, exitStatus, err := runExecCapture(sshClient, flag.Args())
	if len(stdout) > 0 {
		_, _ = os.Stdout.Write(stdout)
	}
	if len(stderr) > 0 {
		_, _ = os.Stderr.Write(stderr)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "go interop client failed: %s\n", err)
		return 1
	}
	return exitStatus
}

func runExecCapture(sshClient *client.Client, command []string) ([]byte, []byte, int, error) {
	channel, err := sshClient.OpenChannel("session", 30_000, 0)
	if err != nil {
		return nil, nil, 1, err
	}
	defer channel.Close()

	commandString := strings.Join(command, " ")
	if commandString == "" {
		commandString = "printf ''"
	}
	if err := channel.SendRequest(&ssh3Messages.ChannelRequestMessage{
		WantReply: false,
		ChannelRequest: &ssh3Messages.ExecRequest{
			Command: commandString,
		},
	}); err != nil {
		return nil, nil, 1, err
	}

	var stdout []byte
	var stderr []byte
	for {
		genericMessage, err := channel.NextMessage()
		if err != nil {
			return stdout, stderr, 1, err
		}
		switch message := genericMessage.(type) {
		case *ssh3Messages.DataOrExtendedDataMessage:
			switch message.DataType {
			case ssh3Messages.SSH_EXTENDED_DATA_NONE:
				stdout = append(stdout, []byte(message.Data)...)
			case ssh3Messages.SSH_EXTENDED_DATA_STDERR:
				stderr = append(stderr, []byte(message.Data)...)
			}
		case *ssh3Messages.ChannelRequestMessage:
			switch request := message.ChannelRequest.(type) {
			case *ssh3Messages.ExitStatusRequest:
				return stdout, stderr, int(request.ExitStatus), nil
			case *ssh3Messages.ExitSignalRequest:
				return stdout, stderr, 1, fmt.Errorf(
					"remote process exited with signal %s: %s",
					request.SignalNameWithoutSig,
					request.ErrorMessageUTF8,
				)
			}
		}
	}
}
