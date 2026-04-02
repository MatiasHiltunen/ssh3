package main

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func main() {
	socketPath := os.Getenv("SSH_AUTH_SOCK")
	if socketPath == "" {
		fmt.Fprintln(os.Stderr, "SSH_AUTH_SOCK is empty")
		os.Exit(1)
	}

	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not dial SSH agent: %v\n", err)
		os.Exit(1)
	}
	defer conn.Close()

	client := agent.NewClient(conn)
	identities, err := client.List()
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not list agent identities: %v\n", err)
		os.Exit(1)
	}
	if len(identities) == 0 {
		fmt.Fprintln(os.Stderr, "agent returned no identities")
		os.Exit(1)
	}

	publicKey, err := ssh.ParsePublicKey(identities[0].Blob)
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not parse agent public key: %v\n", err)
		os.Exit(1)
	}

	signature, err := client.Sign(publicKey, []byte("ssh3-agent-probe"))
	if err != nil {
		fmt.Fprintf(os.Stderr, "could not sign with agent: %v\n", err)
		os.Exit(1)
	}
	if len(signature.Blob) == 0 {
		fmt.Fprintln(os.Stderr, "agent returned an empty signature")
		os.Exit(1)
	}

	fmt.Printf("SSH3_AGENT_PROBE_OK %d %s\n", len(identities), signature.Format)
}
