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
	"testing"

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

func TestUnknownPublicKey(t *testing.T) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		t.Fatal(err)
	}
	filename := "temp_authorized_keys"

	pubkeyBytes := ssh.MarshalAuthorizedKey(public)
	err = ioutil.WriteFile(filename, pubkeyBytes, 0600)
	if err != nil {
		t.Fatalf("failed to create auth keys file: %q", err)
	}
	// 
	identityFilename := "id_temp"
	privateDER := x509.MarshalPKCS1PrivateKey(private)
	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateDER,
	}
	privateBytes := pem.EncodeToMemory(&privateKeyPEM)
	err = ioutil.WriteFile(identityFilename, privateBytes, 0600)
	if err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("./otssh", "--authorized-keys", filename)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("starting process")

	err = cmd.Start()
	if err != nil {
		t.Fatalf("failed to run command: %q\n", err)
	}

	ssh := exec.Command("ssh", "-T", "-i", identityFilename, "-p", "2023", "127.0.0.1")
	sshStdout, err := ssh.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	sshStderr, err := ssh.StderrPipe()
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("starting ssh")
	err = ssh.Start()
	if err != nil {
		t.Fatalf("failed to run ssh: %q\n", err)
	}

	fmt.Println("piping ssh")
	_, err = io.Copy(os.Stdout, sshStdout)
	_, err = io.Copy(os.Stderr, sshStderr)
	if err != nil {
		t.Fatal(err)
	}

	fmt.Println("Going to wait for SSH..")

	if err := ssh.Wait(); err != nil {
		t.Fatal(err)
	}

	fmt.Println("piping output")
	_, err = io.Copy(os.Stdout, stdout)
	_, err = io.Copy(os.Stderr, stderr)

	fmt.Println("done piping")

	if err != nil {
		t.Fatal(err)
	}

	cmd.Process.Kill()
}
