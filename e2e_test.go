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
	"strings"
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

func generateKeyPair() (*os.File, *os.File, func(), error) {
	private, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, nil, err
	}
	public, err := ssh.NewPublicKey(private.Public())
	if err != nil {
		return nil, nil, nil, err
	}

	pubkeyBytes := ssh.MarshalAuthorizedKey(public)

	privateDER := x509.MarshalPKCS1PrivateKey(private)
	privateKeyPEM := pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: privateDER,
	}
	privateBytes := pem.EncodeToMemory(&privateKeyPEM)

	publicKeyFile, err := ioutil.TempFile("./", "id_temp.*.pub")
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = publicKeyFile.Write(pubkeyBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	privateKeyFile, err := ioutil.TempFile("./", "id_temp.*")
	if err != nil {
		return nil, nil, nil, err
	}
	err = os.Chmod(privateKeyFile.Name(), 0600)
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = privateKeyFile.Write(privateBytes)
	if err != nil {
		return nil, nil, nil, err
	}

	cleanup := func() {
		os.Remove(publicKeyFile.Name())
		os.Remove(privateKeyFile.Name())
	}

	return privateKeyFile, publicKeyFile, cleanup, nil
}

func TestUnknownPublicKey(t *testing.T) {
	privateKeyFile, _, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	_, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name())
	cmd.Start()
	if err != nil {
		t.Fatalf("failed to run command: %q\n", err)
	}

	ssh := testcli.Command(
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "2022", "127.0.0.1", "date",
	)
	ssh.Run()

	cmd.Wait()
	expected := "Permission denied (publickey)"
	if !ssh.StderrContains(expected) {
		t.Fatalf("Expected %s, got %s", expected, ssh.Stdout())
	}
}

func TestBindsToPortArgument(t *testing.T) {
	privateKeyFile, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	cmd.Start()

	ssh := testcli.Command(
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "date",
	)

	ssh.Run()
	cmd.Kill()

	expected := "logged in with key"
	// This should be on stdout, not stderr?
	// In addition we should be able to test this on the ssh command, but it seems it
	// doesn't properly handle commands from non-interactive sessions correctly?
	if !cmd.StderrContains(expected) {
		t.Fatalf("exptected otssh output to contain %q, got %q", expected, cmd.Stderr())

	}
}

func TestCannotBindPort(t *testing.T) {
	_, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()

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

func TestConnectionOpenUntilSuccessfullHandshake(t *testing.T) {
	privateKeyFile, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	badPrivateKeyFile, _, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	cmd.Start()

	testcli.Run(
		"ssh", "-T", "-i", badPrivateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1",
	)

	expected := "Failed to perform SSH handshake"
	if !cmd.StderrContains(expected) {
		t.Fatalf("expected %q, got %q", expected, cmd.Stderr())
	}

	ssh := testcli.Command(
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "date",
	)

	ssh.Run()

	expected = "logged in with key"
	if !cmd.StderrContains(expected) {
		t.Fatalf("wanted %q, got %q", expected, cmd.Stderr())
	}

	// After accepting a connection all other connections should be refused
	connectionDenied := testcli.Command(
		"ssh", "-T", "-i", badPrivateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1",
	)
	connectionDenied.Run()
	expected = "connection refused"
	if !connectionDenied.StderrContains(expected) {
		t.Fatalf("exptected %q, got %q", expected, connectionDenied.Stderr())
	}
	cmd.Kill()
}

func TestConnectionOpenUntilTimeout(t *testing.T) {
	_, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234", "--timeout", "1")
	cmd.Start()

	cmd.Wait()

	expected := "Timeout: no connection established"
	if !cmd.StdoutContains(expected) {
		t.Fatalf("expected %q, got %q", expected, cmd.Stdout())
	}
}

func TestNonInteractiveExec(t *testing.T) {
	privateKeyFile, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	cmd.Start()

	ssh := testcli.Command(
		"ssh", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "echo", "'hi you'",
	)
	ssh.Run()
	cmd.Wait()

	expected := "hi you"
	if !cmd.StdoutContains(expected) {
		t.Fatalf("wanted %q, got %q", expected, cmd.Stderr())
	}
	notExpected := "Failed to execute"
	if cmd.StdoutContains(notExpected) {
		t.Fatalf("did not want %q, got %q", notExpected, cmd.Stdout())
	}
}

func TestWritesToLogfile(t *testing.T) {
	privateKeyFile, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	cmd := testcli.Command("./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234", "--log", "test_shell.log")
	cmd.Start()
	defer os.Remove("test_shell.log")

	ssh := testcli.Command(
		"ssh", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "echo", "'hi you'",
	)
	ssh.Run()
	cmd.Wait()

	fmt.Println("ssh output")
	fmt.Println(ssh.Stdout())
	fmt.Println(ssh.Stderr())
	fmt.Println("cmd output")
	fmt.Println(cmd.Stdout())
	fmt.Println(cmd.Stderr())

	expected := "== New session from"
	b, err := ioutil.ReadFile("test_shell.log")
	if err != nil {
		t.Fatalf("could not open log file: %q", err)
	}
	log := string(b)
	if !strings.Contains(log, expected) {
		t.Fatalf("expected %q, got %q", expected, log)
	}
	expected = "echo 'hi you'"
	if !strings.Contains(log, expected) {
		t.Fatalf("expected %q, got %q", expected, log)
	}
}
