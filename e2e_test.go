package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"net"
	"os"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/gerbyzation/testcli"
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

func generateKeyPair() (*os.File, *os.File, error) {
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

	authKeysFile, err := ioutil.TempFile("./", "authorized_keys.*")
	if err != nil {
		return nil, nil, err
	}
	_, err = authKeysFile.Write(pubkeyBytes)
	if err != nil {
		return nil, nil, err
	}

	idFile, err := ioutil.TempFile("./", "id_temp.*")
	if err != nil {
		return nil, nil, err
	}
	err = os.Chmod(authKeysFile.Name(), 0600)
	if err != nil {
		return nil, nil, err
	}
	_, err = idFile.Write(privateBytes)
	if err != nil {
		return nil, nil, err
	}

	return idFile, authKeysFile, nil
}

func TestUnknownPublicKey(t *testing.T) {
	privateKeyFile, _, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(privateKeyFile.Name())

	_, publicKeyFile, err := generateKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(publicKeyFile.Name())

	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name())
	cmd.Start()
	if err != nil {
		t.Fatalf("failed to run command: %q\n", err)
	}

	ssh := testcli.Command(
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "2022", "127.0.0.1",
	)

	ssh.Start()
	ssh.Wait()

	cmd.Kill()
	expected := "Permission denied (publickey)"
	if !ssh.StderrContains(expected) {
		t.Fatalf("Expected %s, got %s", expected, ssh.Stdout())
	}
}

func TestCannotBindPort(t *testing.T) {
	_, publicKeyFile, err := generateKeyPair()
	defer os.Remove(publicKeyFile.Name())

	conn, err := net.Listen("tcp", "0.0.0.0:1234")
	if err != nil {
		t.Fatal("cound not bind to port")
	}

	defer conn.Close()

	testcli.Run("./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	if !testcli.StderrContains("could not bind to port") {
		t.Fatalf("expected could not bind to port, got %q", testcli.Stderr())
	}
}
