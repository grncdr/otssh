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
	"regexp"
	"strings"
	"testing"

	"golang.org/x/crypto/ssh"

	"github.com/rendon/testcli"
)

func TestRaisesErrorForMissingAuthKeysFile(t *testing.T) {
	testcli.Run(t, "./otssh")
	if testcli.Success() {
		t.Fatalf("Expected error, but succeeded: %s", testcli.Stdout())
	}

	if !testcli.StderrContains("Required flag \"authorized-keys\" not set") {
		t.Fatalf("Expected %q to contain %q", testcli.Stderr(), "Required flag \"authorized-keys\" not set")
	}
}

func TestAuthorizedKeysDoesNotExist(t *testing.T) {
	filename := "fake_file"

	testcli.Run(t, "./otssh", "--authorized-keys", filename)
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

	testcli.Run(t, "./otssh", "--authorized-keys", filename)
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

	testcli.Run(t, "./otssh", "--authorized-keys", filename)
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

	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name())
	cmd.Start()

	if !cmd.StdoutContains("Add this to your known_hosts file.") {
		t.Errorf("expected Add this to your known_hosts file., got %q", cmd.Stdout())
	}

	ssh := testcli.Command(
		t,
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
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

	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	cmd.Start()
	defer cmd.Kill()

	if !cmd.StdoutContains("Add this to your known_hosts file.") {
		t.Errorf("expected Add this to your known_hosts file., got %q", cmd.Stdout())
	}

	ssh := testcli.Command(
		t,
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "date",
	)

	ssh.Run()

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

	testcli.Run(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
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

	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	cmd.Start()
	defer cmd.Kill()

	if !cmd.StdoutContains("Add this to your known_hosts file.") {
		t.Errorf("expected Add this to your known_hosts file., got %q", cmd.Stdout())
	}

	testcli.Run(t,
		"ssh", "-T", "-i", badPrivateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1",
	)

	expected := "Failed to perform SSH handshake"
	if !cmd.StderrContains(expected) {
		t.Fatalf("expected %q, got %q", expected, cmd.Stderr())
	}

	ssh := testcli.Command(t,
		"ssh", "-T", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "date",
	)

	ssh.Run()

	expected = "logged in with key"
	if !cmd.StderrContains(expected) {
		t.Fatalf("wanted %q, got %q", expected, cmd.Stderr())
	}

	// After accepting a connection all other connections should be refused
	connectionDenied := testcli.Command(t,
		"ssh", "-T", "-i", badPrivateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1",
	)
	connectionDenied.Run()
	expected = "connection refused"
	if !connectionDenied.StderrContains(expected) {
		t.Fatalf("exptected %q, got %q", expected, connectionDenied.Stderr())
	}
}

func TestConnectionOpenUntilTimeout(t *testing.T) {
	_, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}
	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234", "--timeout", "1")
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

	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234")
	cmd.Start()

	if !cmd.StdoutContains("Add this to your known_hosts file.") {
		t.Errorf("expected Add this to your known_hosts file., got %q", cmd.Stdout())
	}

	ssh := testcli.Command(t,
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

	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234", "--log", "test_shell.log")
	cmd.Start()
	defer os.Remove("test_shell.log")

	if !cmd.StdoutContains("Add this to your known_hosts file.") {
		t.Errorf("expected Add this to your known_hosts file., got %q", cmd.Stdout())
	}

	ssh := testcli.Command(
		t,
		"ssh", "-i", privateKeyFile.Name(),
		"-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
		"-p", "1234", "127.0.0.1", "echo", "'hi you'",
	)
	ssh.Run()
	cmd.Wait()

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

func TestAnnounce(t *testing.T) {
	_, publicKeyFile, cleanup, err := generateKeyPair()
	defer cleanup()
	if err != nil {
		t.Fatal(err)
	}

	cmd := testcli.Command(t, "./otssh", "--authorized-keys", publicKeyFile.Name(), "--port", "1234", "--log", "test_shell.log", "--announce", "echo")
	cmd.Start()
	defer cmd.Kill()
	defer os.Remove("test_shell.log")

	if !cmd.StdoutContains("Add this to your known_hosts file.") {
		t.Errorf("expected Add this to your known_hosts file., got %q", cmd.Stdout())
	}

	re := regexp.MustCompile(`Host public key: (ssh-ed25519 [0-9A-Za-z_/+]+)\nAdd`) // testcli badly joins lines without space
	matched := re.FindStringSubmatch(cmd.Stdout())[1]

	expected := fmt.Sprintf("echo\n%s", matched) // bug in testcli that removes newlines
	if !cmd.StdoutContains(expected) {
		t.Fatalf("wanted %q, got %q", expected, cmd.Stdout())
	}
}
