package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"strings"
	"testing"
	"net"

	"golang.org/x/crypto/ssh"

	"github.com/rendon/testcli"
)

func TestRaisesErrorForMissingAuthKeysFile(t *testing.T) {
	testcli.Run("./otssh")
	if testcli.Success() {
		t.Fatalf("Expected error, but succeeded: %s", testcli.Stdout())
	}

	if !testcli.StderrContains("Required flag \"authorized-keys\" not set") {
		t.Fatalf("Expected %q to contain %q", testcli.Stderr(), "Required flag \"authorized-keys\" not set")
	}
}

func TestAuthorizedKeysDoesNotExist(t *testing.T) {
	filename := "fake_file"

	testcli.Run("./otssh", "--authorized-keys", filename)
	expected := fmt.Sprintf("%s does not exist", filename)

	if testcli.Success() {
		t.Fatalf("Expected command to exit unsucessfully")
	}

	if !testcli.StderrContains(expected) {
		t.Fatalf("Expected %q to contain %s", testcli.Stdout(), expected)
	}
}

func TestAuthorizedKeysNotReadable(t *testing.T) {
	filename := "temp_unreadable_auth_keys"
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		file.Close()
		err := os.Remove(filename)
		if err != nil {
			fmt.Printf("failed to clean up temp auth keys file: %v", err)
		}
	}()

	err = os.Chmod(filename, 0300)
	if err != nil {
		t.Fatal(err)
	}

	testcli.Run("./otssh", "--authorized-keys", filename)
	expected := fmt.Sprintf("%s is not readable", filename)

	if testcli.Success() {
		t.Fatalf("Expected command to exit unsucessfully")
	}

	if !testcli.StderrContains(expected) {
		t.Fatalf("Expected %q to contain %s", testcli.Stderr(), expected)
	}
}

func TestAuthorizedKeysEmpty(t *testing.T) {
	filename := "temp_empty_auth_keys"
	file, err := os.Create(filename)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		file.Close()
		err := os.Remove(filename)
		if err != nil {
			fmt.Printf("failed to clean up temp auth keys file: %v", err)
		}
	}()

	testcli.Run("./otssh", "--authorized-keys", filename)
	expected := fmt.Sprintf("%s contained no keys", filename)

	if testcli.Success() {
		t.Fatalf("Expected command to exit unsucessfully")
	}

	if !testcli.StderrContains(expected) {
		t.Fatalf("Expected %q to contain %s", testcli.Stderr(), expected)
	}
}

func generateKeyPair() (*[]byte, *[]byte, error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil, nil, err
	}

	pubkeyBytes := ssh.MarshalAuthorizedKey(public)

	privateDER := x509.MarshalPKCS1PrivateKey(private)
	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateDER,
	}
	privateBytes := pem.EncodeToMemory(&privateKeyPEM)

	return &privateBytes, &pubkeyBytes, nil
}

func TestUnknownPublicKey(t *testing.T) {
	_, publicBytes, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	filename := "temp_authorized_keys"
	err = ioutil.WriteFile(filename, *publicBytes, 0600)
	if err != nil {
		t.Fatalf("failed to create auth keys file: %q", err)
	}
	defer func() {
		os.Remove(filename)
	}()

	privateBytes, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	identityFilename := "id_temp"
	err = ioutil.WriteFile(identityFilename, *privateBytes, 0600)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		os.Remove(identityFilename)
	}()

	cmd := exec.Command("./otssh", "--authorized-keys", filename)
	stdoutPipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderrPipe, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("starting process")

	err = cmd.Start()
	if err != nil {
		t.Fatalf("failed to run command: %q\n", err)
	}

	ssh := exec.Command(
		"ssh", "-T", "-i", identityFilename,
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "2022", "127.0.0.1",
	)

	sshStdoutPipe, err := ssh.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	sshStderrPipe, err := ssh.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("starting ssh")
	err = ssh.Start()
	if err != nil {
		t.Fatalf("failed to run ssh: %q\n", err)
	}

	fmt.Println("piping ssh")
	sshStdout := new(strings.Builder)
	_, err = io.Copy(sshStdout, sshStdoutPipe)
	if err != nil {
		t.Fatal(err)
	}

	sshStderr := new(strings.Builder)
	_, err = io.Copy(sshStderr, sshStderrPipe)
	if err != nil {
		t.Fatal(err)
	}

	sshErr := ssh.Wait()
	if sshErr == nil {
		t.Fatal("Expected SSH to exit unsuccessfully")
	}

	_, err = io.Copy(os.Stdout, stdoutPipe)
	if err != nil {
		t.Fatal(err)
	}
	_, err = io.Copy(os.Stderr, stderrPipe)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("done piping")

	if err != nil {
		t.Fatal(err)
	}

	if sshErr != nil {
		cmd.Process.Kill()
		expected := "Permission denied (publickey)"
		if !strings.Contains(sshStderr.String(), expected) {
			t.Fatalf("Expected %s, got %s", expected, sshStderr.String())
		}
		fmt.Println("sshStder")
		fmt.Println(sshStderr)
		fmt.Println(sshStdout)
	}
}

func TestCannotBindPort(t *testing.T) {
	_, publicBytes, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}

	filename := "temp_authorized_keys"
	err = ioutil.WriteFile(filename, *publicBytes, 0600)
	if err != nil {
		t.Fatalf("failed to create auth keys file: %q", err)
	}
	defer func() {
		os.Remove(filename)
	}()

	conn, err := net.Listen("tcp", "0.0.0.0:1234")
	if err != nil {
		t.Fatal("cound not bind to port")
	}

	defer conn.Close()

	testcli.Run("./otssh", "--authorized-keys", filename, "--port", "1234")
	if !testcli.StderrContains("could not bind to port") {
		t.Fatalf("expected could not bind to port, got %q", testcli.Stderr())
	}
}
