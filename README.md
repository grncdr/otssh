# otssh

`otssh` is an SSH server for providing audited, single-use shell sessions from environments where a persistent daemon is undesirable.

## Usage

```
usage: otssh [-port=2022] [-log=<filename>] [-announce=<cmd>] -authorized-keys=<filename>

Starts an SSH server with a new host key that will run for exactly one session.
```

## Bounty

This is a **bounty repo**. I would like this tool to exist, and I might even write it myself eventually, but I'd gladly pay somebody else for a working free (as in freedom) version.

### Rules

1. The bounty is currently **500 €**. This is my own money, not a corporate sponsorship.
2. You must open an issue here to say you're starting an implementation, this is so we can agree on a payment method (and to prevent two people claiming the bounty at the same time).
3. The code must be licensed under the AGPLv3.

### Requirements

1. Any language is fine, but the code must build into a single self-contained binary that runs on linux-amd64.
2. The implementation must implement the command line options and process lifecycle described below. Stylistic differences (e.g. `--flag` instead of `-flag`) are acceptable.

## Command line options

### -authorized-keys=\<filename>

**Required** must be in the `authorized_keys` format used by OpenSSH. Use `-` for stdin.

### -port=N

Listen on the specified port number. Defaults to `2022`.

### -log=\<filename>

If provided, write all input and output to the given file, creating a transcript of the shell session. Defaults to stdout.

### -announce=\<cmd>

If provided, the given command will be executed with a single argument, which will be the public key of the server in a format suitable for appending to an OpenSSH `known_hosts` file. For example: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbnqQ/SGC/OWnL4cQGxlZcFxxfCVx0mD+1MlF/Zdidu`.

## Process lifecycle

When you run `otssh` it goes through the following steps.

1. Load authorized keys into memory.
2. Copies all current environment variables.
3. Generate a new ed25519 keypair and prints the public key to STDOUT in the same format as `--announce`.
5. Opens the listening TCP socket.
4. Announce the public key and port. (see the `--announce` documentation above).
6. Accepts a connection on that socket.
7. Authenticate the connection using the provided authorized keys.
8. Does not accept any new connections.
8. Start a shell subprocess using the current value of `$SHELL`, forwarding the current environment, and input/output streams connected to the socket.
9. Wait for shell to exit.
10. Closes the port.
11. Exits with the exit code from step 9.

## Errors

In the case of problems `otssh` will exit with a non-zero status code and print one of the following errors to the stderr stream:

### authorized keys invalid: $filename

Reported in any circumstance where the public keys file is not valid. This error may include additional details about what went wrong, such as:

- $filename does not exist.
- $filename is not readable.
- $filename contains unparseable data.
- $filename contained no keys.

### Invalid announce command: $cmd
  
Reported when the given announce command is not found or not executable.

### Announce failed: $exit_code $stderr

Reported when the announce command exited with non-zero status code.

### Could not bind to port

Reported when the process could not bind to the port to accept connections.

### Connection closed unexpectedly

Reported when the remote side terminates the connection unexpectedly.

### Could not write to log file

Reported when the `--log` option is provided and does not refer to a writable destination.
