package integration_tests

import (
	"context"
	"errors"
	"fmt"
	"io"
	"math/rand"
	"net"
	"os"
	"os/exec"
	osuser "os/user"
	"path"
	"time"

	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
	"golang.org/x/crypto/ssh"
)

var ssh3Path string
var ssh3ServerPath string

const DEFAULT_URL_PATH = "/ssh3-tests"
const DEFAULT_PROXY_URL_PATH = "/ssh3-tests-proxy"

var serverCommand *exec.Cmd
var serverSessions map[string]*Session = make(map[string]*Session) // bind address to session
var proxyServerCommand *exec.Cmd
var proxyServerSession *Session
var rsaPrivKeyPath string
var ed25519PrivKeyPath string
var ecdsaPrivKeyPath string
var attackerPrivKeyPath string
var username string
var ecdsaUsername string

const serverBind = "127.0.0.1:4433"
const proxyServerBind = "127.0.0.1:4444"

var oldServerBinds map[string]string = map[string]string{
	"v0.1.5-rc1": "127.0.0.1:5000",
	"v0.1.5-rc5": "127.0.0.1:5001",
} // tag version to bind string

func IPv6LoopbackAvailable() bool {
	// Probe the capability we need; interface enumeration may require netlink
	// permissions even when IPv6 loopback sockets work.
	conn, err := net.ListenPacket("udp6", "[::1]:0")
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// Register cleanup immediately so a failed assertion cannot leak a child process.
func startClient(command *exec.Cmd) *Session {
	session, err := Start(command, GinkgoWriter, GinkgoWriter)
	Expect(err).ToNot(HaveOccurred())
	DeferCleanup(func() { session.Kill().Wait(5 * time.Second) })
	return session
}

func replaceFixtureFile(filename string, contents []byte) {
	original, err := os.ReadFile(filename)
	existed := err == nil
	if err != nil {
		Expect(errors.Is(err, os.ErrNotExist)).To(BeTrue(), "read original fixture")
	}
	DeferCleanup(func() {
		if existed {
			Expect(os.WriteFile(filename, original, 0o644)).To(Succeed())
		} else {
			Expect(os.Remove(filename)).To(Succeed())
		}
	})
	Expect(os.WriteFile(filename, contents, 0o644)).To(Succeed())
}

var _ = BeforeSuite(func() {
	var err error
	ssh3Path, err = Build("../cmd/ssh3/main.go")
	Expect(err).ToNot(HaveOccurred())
	if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") == "1" {
		// Tests implying a server will only work on Linux
		// (the server currently only builds on Linux)
		// and the server needs root priviledges, so we only
		// run them is they are enabled explicitly.
		ssh3ServerPath, err = BuildWithEnvironment("../cmd/ssh3-server/main.go", []string{fmt.Sprintf("CGO_ENABLED=%s", os.Getenv("CGO_ENABLED"))})
		Expect(err).ToNot(HaveOccurred())
		serverCommand = exec.Command(ssh3ServerPath,
			"-bind", serverBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		serverCommand.Env = append(os.Environ(), "SSH3_LOG_LEVEL=debug")
		session, err := Start(serverCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[serverBind] = session

		for tag, bind := range oldServerBinds {
			gobin, err := os.MkdirTemp("", fmt.Sprintf("ssh3-backwards-compatible-versions-%s", tag))
			Expect(err).ToNot(HaveOccurred())
			cmd := exec.Command("go", "install", fmt.Sprintf("github.com/francoismichel/ssh3/cmd/ssh3-server@%s", tag))
			cmd.Env = os.Environ()
			cmd.Env = append(cmd.Env, fmt.Sprintf("GOBIN=%s", gobin))
			cmd.Stdout, cmd.Stderr = GinkgoWriter, GinkgoWriter
			DeferCleanup(os.RemoveAll, gobin)
			err = cmd.Run()
			Expect(err).ToNot(HaveOccurred())
			serverPath := path.Join(gobin, "ssh3-server")
			Expect(err).ToNot(HaveOccurred())
			backwardsCompatibleServerCommand := exec.Command(serverPath,
				"-bind", bind,
				"-v",
				"-enable-password-login",
				"-url-path", DEFAULT_URL_PATH,
				"-cert", os.Getenv("CERT_PEM"),
				"-key", os.Getenv("CERT_PRIV_KEY"))
			backwardsCompatibleServerCommand.Env = append(os.Environ(), "SSH3_LOG_LEVEL=debug")
			session, err = Start(backwardsCompatibleServerCommand, GinkgoWriter, GinkgoWriter)
			Expect(err).ToNot(HaveOccurred())
			serverSessions[bind] = session
		}

		proxyServerCommand = exec.Command(ssh3ServerPath,
			"-bind", proxyServerBind,
			"-v",
			"-enable-password-login",
			"-url-path", DEFAULT_PROXY_URL_PATH,
			"-cert", os.Getenv("CERT_PEM"),
			"-key", os.Getenv("CERT_PRIV_KEY"))
		proxyServerCommand.Env = append(os.Environ(), "SSH3_LOG_LEVEL=debug")
		proxyServerSession, err = Start(proxyServerCommand, GinkgoWriter, GinkgoWriter)
		Expect(err).ToNot(HaveOccurred())

		serverSessions[proxyServerBind] = proxyServerSession

		rsaPrivKeyPath = os.Getenv("TESTUSER_PRIVKEY")
		ed25519PrivKeyPath = os.Getenv("TESTUSER_ED25519_PRIVKEY")
		ecdsaPrivKeyPath = os.Getenv("TESTUSER_ECDSA_PRIVKEY")
		attackerPrivKeyPath = os.Getenv("ATTACKER_PRIVKEY")
		username = os.Getenv("TESTUSER_USERNAME")
		ecdsaUsername = os.Getenv("ECDSATESTUSER_USERNAME")
		Expect(fileExists(rsaPrivKeyPath)).To(BeTrue())
		Expect(fileExists(attackerPrivKeyPath)).To(BeTrue())
		user, err := osuser.Lookup(username)
		Expect(err).ToNot(HaveOccurred())
		replaceFixtureFile(path.Join(user.HomeDir, ".profile"), []byte("echo 'hello from .profile'\n"))
	}
})

var _ = AfterSuite(func() {
	CleanupBuildArtifacts()
	for _, serverSession := range serverSessions {
		serverSession.Kill().Wait(5 * time.Second)
	}
})

var _ = Describe("Testing the ssh3 cli", func() {

	Context("Usage", func() {
		It("Displays the help", func() {
			command := exec.Command(ssh3Path, "-h")
			session := startClient(command)
			Eventually(session).Should(Exit(0))
			Expect(session.Err.Contents()).To(ContainSubstring("Usage of"))
		})
	})

	Context("With running server", func() {
		BeforeEach(func() {
			if os.Getenv("SSH3_INTEGRATION_TESTS_WITH_SERVER_ENABLED") != "1" {
				Skip("skipping integration tests")
			}
			Consistently(serverSessions[serverBind], "200ms").ShouldNot(Exit())
		})

		Context("Insecure", func() {
			var clientArgs []string
			getClientArgsWithBind := func(privKeyPath string, bind string, additionalArgs ...string) []string {
				args := []string{
					"-v",
					"-insecure",
					"-privkey", privKeyPath,
				}
				args = append(args, additionalArgs...)
				args = append(args, fmt.Sprintf("%s@%s%s", username, bind, DEFAULT_URL_PATH))
				return args
			}
			getClientArgs := func(privKeyPath string, additionalArgs ...string) []string {
				return getClientArgsWithBind(privKeyPath, serverBind, additionalArgs...)
			}

			Context("Client behaviour", func() {
				It("Should connect using an RSA privkey", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session := startClient(command)
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an RSA privkey through proxy jump", func() {
					clientArgs = append(getClientArgs(rsaPrivKeyPath, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH)), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session := startClient(command)
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				for key, val := range oldServerBinds {
					// actually capture the values of key,val, as directly referring them in the code below will only keep the value of the last iteration
					tag, bind := key, val
					When("server version is"+tag+", bind is"+bind, func() {
						It("Should connect using an RSA privkey to old supported server", func() {
							clientArgs = append(getClientArgsWithBind(rsaPrivKeyPath, bind), "echo", "Hello, World!")
							command := exec.Command(ssh3Path, clientArgs...)
							session := startClient(command)
							Eventually(session).Should(Exit(0))
							Eventually(session).Should(Say("Hello, World!\n"))
						})
					})
				}

				It("Should connect using an ed25519 privkey", func() {
					clientArgs = append(getClientArgs(ed25519PrivKeyPath), "echo", "Hello, World!")
					command := exec.Command(ssh3Path, clientArgs...)
					session := startClient(command)
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("Should connect using an ecdsa privkey", func() {
					if ecdsaUsername == username {
						user, err := osuser.Lookup(username)
						Expect(err).ToNot(HaveOccurred())
						privateKey, err := os.ReadFile(ecdsaPrivKeyPath)
						Expect(err).ToNot(HaveOccurred())
						signer, err := ssh.ParsePrivateKey(privateKey)
						Expect(err).ToNot(HaveOccurred())
						replaceFixtureFile(path.Join(user.HomeDir, ".ssh3", "authorized_identities"), ssh.MarshalAuthorizedKey(signer.PublicKey()))
					}

					// for retrocopatibility integration tests with version 0.1.5, we must perform ecdsa tests
					// for another user as ecdsa is not available on the server on older versions
					savedUsername := username
					username = ecdsaUsername
					clientArgs = append(getClientArgs(ecdsaPrivKeyPath), "echo", "Hello, World!")
					username = savedUsername
					command := exec.Command(ssh3Path, clientArgs...)
					session := startClient(command)
					Eventually(session).Should(Exit(0))
					Eventually(session).Should(Say("Hello, World!\n"))
				})

				It("preserves stdout and stderr from fast commands before exit status", func() {
					for range 12 {
						args := append(getClientArgs(rsaPrivKeyPath), "printf '__ssh3_stdout__'; printf '__ssh3_stderr__' >&2")
						session := startClient(exec.Command(ssh3Path, args...))
						Eventually(session).Should(Exit(0))
						Expect(session.Out.Contents()).To(ContainSubstring("__ssh3_stdout__"))
						Expect(session.Err.Contents()).To(ContainSubstring("__ssh3_stderr__"))
					}
				})

				It("Should return the correct exit status", func() {
					clientArgs0 := append(getClientArgs(rsaPrivKeyPath), "exit", "0")
					clientArgs1 := append(getClientArgs(rsaPrivKeyPath), "exit", "1")
					clientArgs255 := append(getClientArgs(rsaPrivKeyPath), "exit", "255")
					clientArgsMinus1 := append(getClientArgs(rsaPrivKeyPath), "exit", "-1")

					command0 := exec.Command(ssh3Path, clientArgs0...)
					session := startClient(command0)
					Eventually(session).Should(Exit(0))

					command1 := exec.Command(ssh3Path, clientArgs1...)
					session = startClient(command1)
					Eventually(session).Should(Exit(1))

					command255 := exec.Command(ssh3Path, clientArgs255...)
					session = startClient(command255)
					Eventually(session).Should(Exit(255))

					commandMinus1 := exec.Command(ssh3Path, clientArgsMinus1...)
					session = startClient(commandMinus1)
					Eventually(session).Should(Exit(255))
				})

				It("Should run the interactive shell in login mode and read .profile", func() {
					clientArgs = getClientArgs(rsaPrivKeyPath)
					command := exec.Command(ssh3Path, clientArgs...)
					stdin, err := command.StdinPipe()
					Expect(err).ToNot(HaveOccurred())
					session := startClient(command)
					Consistently(session).ShouldNot(Exit())
					Eventually(session.Out).Should(Say("hello from .profile"))
					_, err = stdin.Write([]byte("exit\n")) // 0x04 = EOT character, closing the bash session
					Expect(err).ToNot(HaveOccurred())
					Eventually(session).Should(Exit(0))
				})

				// It checks that upon executing the client with the -forward-tcp,
				// a TCP socket is indeed well open on the client and is indeed forwarded
				// through the SSH3 connection towards the specified remote IP and port.
				Context("TCP port forwarding", func() {
					testTCPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.TCPAddr, messageFromClient string, messageFromServer string) {
						localIP := "::1"
						if remoteAddr.IP.To4() != nil {
							localIP = "127.0.0.1"
						}
						ctx, cancel := context.WithCancel(context.Background())
						listener, err := net.ListenTCP("tcp", remoteAddr)
						Expect(err).ToNot(HaveOccurred())
						serverDone := make(chan struct{})
						DeferCleanup(func() {
							cancel()
							listener.Close()
							Eventually(serverDone, 5*time.Second).Should(BeClosed())
						})
						go func() {
							defer close(serverDone)
							defer GinkgoRecover()
							conn, err := listener.AcceptTCP()
							if err != nil && ctx.Err() != nil {
								return
							}
							Expect(err).ToNot(HaveOccurred())
							defer conn.Close()
							stop := context.AfterFunc(ctx, func() { conn.Close() })
							defer stop()
							Expect(conn.SetDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
							buffer := make([]byte, len(messageFromClient))
							_, err = io.ReadFull(conn, buffer)
							if err != nil && ctx.Err() != nil {
								return
							}
							Expect(err).ToNot(HaveOccurred())
							Expect(string(buffer)).To(Equal(messageFromClient))
							_, err = conn.Write([]byte(messageFromServer))
							if err != nil && ctx.Err() != nil {
								return
							}
							Expect(err).ToNot(HaveOccurred())
							Expect(conn.CloseWrite()).To(Succeed())
							n, err := conn.Read(buffer)
							if err != nil && ctx.Err() != nil {
								return
							}
							Expect(err).To(Equal(io.EOF))
							Expect(n).To(Equal(0))
						}()
						additionalArgs := []string{}
						if proxyJump {
							additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
						}
						additionalArgs = append(additionalArgs, "-forward-tcp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
						session := startClient(exec.Command(ssh3Path, getClientArgs(rsaPrivKeyPath, additionalArgs...)...))
						localAddr := net.JoinHostPort(localIP, fmt.Sprint(localPort))
						var conn net.Conn
						Eventually(func() error {
							var err error
							conn, err = net.DialTimeout("tcp", localAddr, time.Second)
							return err
						}, 5*time.Second).Should(Succeed(), "%s", session.Err.Contents())
						DeferCleanup(conn.Close)
						Expect(conn.SetDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
						_, err = conn.Write([]byte(messageFromClient))
						Expect(err).ToNot(HaveOccurred())
						Expect(conn.(*net.TCPConn).CloseWrite()).To(Succeed())
						buffer := make([]byte, len(messageFromServer))
						_, err = io.ReadFull(conn, buffer)
						Expect(err).ToNot(HaveOccurred())
						Expect(string(buffer)).To(Equal(messageFromServer))
						n, err := conn.Read(buffer)
						Expect(n).To(Equal(0))
						Expect(err).To(Equal(io.EOF))
					}

					It("works with small messages", func() {
						testTCPPortForwarding(8080, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
					})

					It("works through proxy jump", func() {
						testTCPPortForwarding(8080, true, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
					})

					It("works with messages larger than a typical MTU", func() {
						rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
						messageFromClient := make([]byte, 20000)
						messageFromServer := make([]byte, 20000)
						n, err := rng.Read(messageFromClient)
						Expect(n).To(Equal(len(messageFromClient)))
						Expect(err).ToNot(HaveOccurred())
						n, err = rng.Read(messageFromServer)
						Expect(n).To(Equal(len(messageFromServer)))
						Expect(err).ToNot(HaveOccurred())
						testTCPPortForwarding(8081, false, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer))
					})

					It("works with IPv6 addresses", func() {
						// we first have to check whether IPv6 are enabled on that host, it is still often
						// not the case in many Docker containers...
						if !IPv6LoopbackAvailable() {
							Skip("IPv6 not available on this host")
						}
						testTCPPortForwarding(8082, false, &net.TCPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
					})
				})
			})

			// It checks that upon executing the client with the -forward-udp,
			// a UDP socket is indeed well open on the client and is indeed forwarded
			// through the SSH3 connection towards the specified remote IP and port.
			Context("UDP port forwarding", func() {
				testUDPPortForwarding := func(localPort uint16, proxyJump bool, remoteAddr *net.UDPAddr, messageFromClient, messageFromServer string, oversizedFirst ...bool) {
					localIP := "::1"
					if remoteAddr.IP.To4() != nil {
						localIP = "127.0.0.1"
					}
					sendOversized := len(oversizedFirst) > 0 && oversizedFirst[0]
					ctx, cancel := context.WithCancel(context.Background())
					remoteConn, err := net.ListenUDP("udp", remoteAddr)
					Expect(err).ToNot(HaveOccurred())
					serverDone := make(chan struct{})
					DeferCleanup(func() {
						cancel()
						remoteConn.Close()
						Eventually(serverDone, 5*time.Second).Should(BeClosed())
					})
					go func() {
						defer close(serverDone)
						defer GinkgoRecover()
						Expect(remoteConn.SetReadDeadline(time.Now().Add(10 * time.Second))).To(Succeed())
						buffer := make([]byte, 2*len(messageFromClient))
						n, clientAddr, err := remoteConn.ReadFromUDP(buffer)
						if err != nil && ctx.Err() != nil {
							return
						}
						Expect(err).ToNot(HaveOccurred())
						Expect(clientAddr.IP.String()).To(Equal(localIP))
						Expect(string(buffer[:n])).To(Equal(messageFromClient))
						if sendOversized {
							_, err = remoteConn.WriteToUDP(make([]byte, 1500), clientAddr)
							Expect(err).ToNot(HaveOccurred())
						}
						_, err = remoteConn.WriteToUDP([]byte(messageFromServer), clientAddr)
						Expect(err).ToNot(HaveOccurred())
					}()
					additionalArgs := []string{}
					if proxyJump {
						additionalArgs = append(additionalArgs, "-proxy-jump", fmt.Sprintf("%s@%s%s", username, proxyServerBind, DEFAULT_PROXY_URL_PATH))
					}
					additionalArgs = append(additionalArgs, "-forward-udp", fmt.Sprintf("%d/%s@%d", localPort, remoteAddr.IP, remoteAddr.Port))
					session := startClient(exec.Command(ssh3Path, getClientArgs(rsaPrivKeyPath, additionalArgs...)...))
					// RunSession starts only after ForwardUDP has bound its listener.
					Eventually(session.Err, 5*time.Second).Should(Say("opened new session channel"))
					localAddr := net.JoinHostPort(localIP, fmt.Sprint(localPort))
					conn, err := net.Dial("udp", localAddr)
					Expect(err).ToNot(HaveOccurred())
					DeferCleanup(conn.Close)
					Expect(conn.SetDeadline(time.Now().Add(5 * time.Second))).To(Succeed())
					if sendOversized {
						_, err = conn.Write(make([]byte, 1500))
						Expect(err).ToNot(HaveOccurred())
					}
					n, err := conn.Write([]byte(messageFromClient))
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromClient)))
					buffer := make([]byte, 2*len(messageFromServer))
					n, err = conn.Read(buffer)
					Expect(err).ToNot(HaveOccurred())
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(string(buffer[:n])).To(Equal(messageFromServer))
				}

				It("works with small messages", func() {
					testUDPPortForwarding(8080, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
				})

				It("works through proxy jump", func() {
					testUDPPortForwarding(8080, true, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello from client", "hello from server")
				})

				// Due to current quic-go limitations, the max datagram size is limited to 1200, whatever the real MTU is,
				// so right now we test for 1150 messages and nothing more
				It("works with messages of 1150 bytes", func() {
					rng := rand.New(rand.NewSource(GinkgoRandomSeed()))
					messageFromClient := make([]byte, 1150)
					messageFromServer := make([]byte, 1150)
					n, err := rng.Read(messageFromClient)
					Expect(n).To(Equal(len(messageFromClient)))
					Expect(err).ToNot(HaveOccurred())
					n, err = rng.Read(messageFromServer)
					Expect(n).To(Equal(len(messageFromServer)))
					Expect(err).ToNot(HaveOccurred())
					testUDPPortForwarding(8081, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, string(messageFromClient), string(messageFromServer))
				})

				It("keeps forwarding after oversized datagrams in either direction", func() {
					testUDPPortForwarding(8081, false, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: 9090}, "hello after oversized client packet", "hello after oversized server packet", true)
				})

				It("works with IPv6 addresses", func() {
					// Check whether IPv6 is available on the host
					if !IPv6LoopbackAvailable() {
						Skip("IPv6 not available on this host")
					}
					testUDPPortForwarding(8082, false, &net.UDPAddr{IP: net.ParseIP("::1"), Port: 9091}, "hello from client", "hello from server")
				})

			})

			Context("Server behaviour", func() {
				It("Should not grand access to non-authorized identity", func() {
					clientArgs = append(getClientArgs(attackerPrivKeyPath), "echo", "Hello, World!")

					command := exec.Command(ssh3Path, clientArgs...)
					session := startClient(command)
					Eventually(session).Should(Exit())
					Eventually(session).ShouldNot(Exit(0))
					Eventually(string(session.Wait().Err.Contents())).Should(ContainSubstring("unauthorized"))
				})
			})
		})
	})
})
