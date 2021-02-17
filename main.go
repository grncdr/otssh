package main

import (
	"bufio"
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"github.com/mikesmitty/edkey"
	"github.com/urfave/cli/v2"
	"golang.org/x/crypto/ssh"
)

func main() {
	app := &cli.App{
		Flags: []cli.Flag{
			&cli.StringFlag{
				Name:     "authorized-keys",
				Usage:    "location of authorized-keys file",
				Required: true,
			},
			&cli.IntFlag{
				Name:  "port",
				Value: 2022,
				Usage: "Port to bind to",
			},
		},
		Name:   "otssh",
		Usage:  "make one time only SSH session",
		Action: run,
	}

	err := app.Run(os.Args)
	if err != nil {
		fmt.Fprint(os.Stderr, err)
		os.Exit(1)
	}
}

func run(c *cli.Context) error {
	log.Println("Started")
	authKeysPath := c.String("authorized-keys")
	port := c.Int("port")

	// Create an io.Reader for the authorized-keys file from either stdin or the
	// file path.
	var authKeysReader io.Reader
	if authKeysPath == "-" {
		authKeysReader = os.Stdin
		log.Println("Reading authorized-keys from stdin")
	} else {
		log.Printf("Reading authorized-keys from %s", authKeysPath)
		f, err := os.Open(authKeysPath)
		if err != nil {
			if errors.Is(err, os.ErrPermission) {
				return fmt.Errorf("authorization key invalid: %s is not readable", authKeysPath)
			} else if errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("authorization key invalid: %s does not exist", authKeysPath)
			} else {
				return fmt.Errorf("authorization key invalid: failed to open %s: %v", authKeysPath, err)
			}
		}

		authKeysReader = bufio.NewReader(f)
	}

	log.Println("Parsing authorized-keys")
	authorizedKeysMap, err := readAuthKeys(authKeysReader)
	if err != nil {
		if authKeysPath == "-" {
			return fmt.Errorf("authorization keys invalid: stdin %v", err)
		}
		return fmt.Errorf("authorization keys invalid: %s %v", authKeysPath, err)
	}
	log.Printf("Found %v keys in authorized-keys file", len(authorizedKeysMap))

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				// Record the fingerprint of the public key used for authentication
				return &ssh.Permissions{
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("Unknown public key for %q", c.User())
		},
	}

	_, privateBytes, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("Failed to generate host key: %v", err)
	}

	// crypto.Signer has a Public method, while ssh.Signer has
	// PublicKey...🤷🏻‍♂️
	privatePEM := pem.Block{
		Type:  "OPENSSH PRIVATE KEY",
		Bytes: edkey.MarshalED25519PrivateKey(privateBytes),
	}
	privatePEMBytes := pem.EncodeToMemory(&privatePEM)
	private, err := ssh.ParsePrivateKey(privatePEMBytes)
	if err != nil {
		return fmt.Errorff("Failed to parse host private key: %v", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	address := fmt.Sprintf("0.0.0.0:%d", port)
	listener, err := net.Listen("tcp", address)
	if err != nil {
		return fmt.Errorf("Could not bind to port %d", port)
	}

	nConn, err := listener.Accept()
	if err != nil {
		return fmt.Errorf("failed to accept incoming connection: %q", err)
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		return fmt.Errorf("failed to perform SSH handshake: %q", err)
	}
	log.Printf("logged in with key %s", conn.Permissions.Extensions["pubkey-fp"])

	// The incoming Request channel must be serviced.
	go ssh.DiscardRequests(reqs)

	// Service the incoming Channel channel.
	for newChannel := range chans {
		// Channels have a type, depending on the application level
		// protocol intended. In the case of a shell, the type is
		// "session" and ServerShell may be used to present a simple
		// terminal interface.
		if newChannel.ChannelType() != "session" {
			newChannel.Reject(ssh.UnknownChannelType, "unknown channel type")
			continue
		}
		channel, requests, err := newChannel.Accept()
		if err != nil {
			log.Fatalf("Could not accept channel: %v", err)
		}

		shell := exec.Command(os.Getenv("SHELL"))

		close := func() {
			channel.Close()
			_, err := shell.Process.Wait()
			if err != nil {
				log.Printf("Failed to exit shell(%s)", err)
			}
			log.Printf("Session closed")
		}

		// Allocate a terminal
		log.Println("Creating pty...")
		shellf, err := pty.Start(shell)
		if err != nil {
			log.Printf("Could not start pty (%s)", err)
			close()
			return nil
		}

		// pipe session to bash and visa-versa
		var once sync.Once
		go func() {
			io.Copy(io.MultiWriter(channel, os.Stdout), shellf)
			once.Do(close)
		}()
		go func() {
			io.Copy(shellf, channel)
			once.Do(close)
		}()

		// Sessions have out-of-band requests such as "shell",
		// "pty-req" and "env".  Here we handle only the
		// "shell" request.
		go func(in <-chan *ssh.Request) {
			for req := range in {
				switch req.Type {
				case "shell":
					// We only accept the default shell
					// (i.e. no command in the Payload
					if len(req.Payload) == 0 {
						req.Reply(true, nil)
					}
				case "pty-req":
					// fmt.Printf("resizing: %+v\n", req)
					termLen := req.Payload[3]
					w, h := parseDims(req.Payload[termLen+4:])
					SetWinsize(shellf.Fd(), w, h)
					// Responding true (OK) here will let the client
					// know we have a pty ready for input
					req.Reply(true, nil)
				case "window-change":
					w, h := parseDims(req.Payload)
					SetWinsize(shellf.Fd(), w, h)
				}
			}
		}(requests)
	}

	return nil
}

func readAuthKeys(source io.Reader) (map[string]bool, error) {
	buf := new(bytes.Buffer)
	buf.ReadFrom(source)
	authorizedKeysBytes := buf.Bytes()

	authorizedKeysMap := map[string]bool{}
	if len(authorizedKeysBytes) == 0 {
		return nil, errors.New("contained no keys")
	}

	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			return nil, errors.New("contained no keys")
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}
	return authorizedKeysMap, nil
}

func parseDims(b []byte) (uint32, uint32) {
	w := binary.BigEndian.Uint32(b)
	h := binary.BigEndian.Uint32(b[4:])
	return w, h
}

// Winsize stores the Height and Width of a terminal.
type Winsize struct {
	Height uint16
	Width  uint16
	x      uint16 // unused
	y      uint16 // unused
}

// SetWinsize sets the size of the given pty.
func SetWinsize(fd uintptr, w, h uint32) {
	ws := &Winsize{Width: uint16(w), Height: uint16(h)}
	syscall.Syscall(syscall.SYS_IOCTL, fd, uintptr(syscall.TIOCSWINSZ), uintptr(unsafe.Pointer(ws)))
}
