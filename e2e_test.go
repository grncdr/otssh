package e2e

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
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
	var errBuffer bytes.Buffer
	var outBuffer bytes.Buffer
	cmd.Stdout = &outBuffer
	cmd.Stderr = &errBuffer

	err = cmd.Run()
	if err != nil {
		fmt.Println(outBuffer.String())
		fmt.Println(errBuffer.String())
		t.Fatalf("failed to run command: %q\n", err)
	}

	var sshErrBuffer, sshOutBuffer bytes.Buffer
	ssh := exec.Command("ssh", "-T", "-i", identityFilename, "exit")
	ssh.Stdout = &sshOutBuffer
	ssh.Stderr = &sshErrBuffer
	err = ssh.Run()
	if err != nil {
		fmt.Println(sshOutBuffer.String())
		fmt.Println(sshErrBuffer.String())
		t.Fatalf("failed to run ssh: %q\n", err)
	}

	ssh.Process.Kill()
	fmt.Println(sshOutBuffer.String())
	fmt.Println(sshErrBuffer.String())

	cmd.Process.Kill()
}
