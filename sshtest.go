package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"os"
	"os/exec"
	"sync"
	"syscall"
	"unsafe"

	"github.com/creack/pty"
	"golang.org/x/crypto/ssh"
)

func main() {
	// Public key authentication is done by comparing
	// the public key of a received connection
	// with the entries in the authorized_keys file.
	authorizedKeysBytes, err := ioutil.ReadFile("authorized_keys")
	if err != nil {
		log.Fatalf("Failed to load authorized_keys, err: %v", err)
	}

	authorizedKeysMap := map[string]bool{}
	for len(authorizedKeysBytes) > 0 {
		pubKey, _, _, rest, err := ssh.ParseAuthorizedKey(authorizedKeysBytes)
		if err != nil {
			log.Fatal(err)
		}

		authorizedKeysMap[string(pubKey.Marshal())] = true
		authorizedKeysBytes = rest
	}

	// An SSH server is represented by a ServerConfig, which holds
	// certificate details and handles authentication of ServerConns.
	config := &ssh.ServerConfig{
		PublicKeyCallback: func(c ssh.ConnMetadata, pubKey ssh.PublicKey) (*ssh.Permissions, error) {
			if authorizedKeysMap[string(pubKey.Marshal())] {
				return &ssh.Permissions{
					// Record the public key used for authentication.
					Extensions: map[string]string{
						"pubkey-fp": ssh.FingerprintSHA256(pubKey),
					},
				}, nil
			}
			return nil, fmt.Errorf("unknown public key for %q", c.User())
		},
	}

	privateBytes, err := ioutil.ReadFile("id_rsa")
	if err != nil {
		log.Fatal("Failed to load private key: ", err)
	}

	private, err := ssh.ParsePrivateKey(privateBytes)
	if err != nil {
		log.Fatal("Failed to parse private key: ", err)
	}

	config.AddHostKey(private)

	// Once a ServerConfig has been configured, connections can be
	// accepted.
	listener, err := net.Listen("tcp", "0.0.0.0:2022")
	if err != nil {
		log.Fatal("failed to listen for connection: ", err)
	}
	nConn, err := listener.Accept()
	if err != nil {
		log.Fatal("failed to accept incoming connection: ", err)
	}

	// Before use, a handshake must be performed on the incoming
	// net.Conn.
	conn, chans, reqs, err := ssh.NewServerConn(nConn, config)
	if err != nil {
		log.Fatal("failed to handshake: ", err)
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

		shell := exec.Command("bash")

		close := func() {
			channel.Close()
			_, err := shell.Process.Wait()
			if err != nil {
				log.Printf("Failed to exit shell(%s)", err)
			}
			log.Printf("Session closed")
		}

		// Allocate a terminal
		log.Print("Creating pty...")
		shellf, err := pty.Start(shell)
		if err != nil {
			log.Printf("Could not start pty (%s)", err)
			close()
			return
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
