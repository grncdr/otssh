# otssh

`otssh` is an SSH server for providing audited, single-use shell sessions from environments where a persistent daemon is undesirable.

## Usage

```
usage: otssh [-port=2022] [-log=<filename>] [-announce=<cmd>] -authorized-keys=<filename>

Starts an SSH server with a new host key that will run for exactly one session.
```

## Example use case

When operating services in a managed container environment (e.g. Amazons Fargate) you may not have access to the host system running your container. In particular, it's often not possible to use docker exec to run a shell in the same environment that your service runs.

You can of course include or some other small SSH daemon in your image, but managing (and auditing) access to that brings more complexity. The design of otssh is such that it does not present any persistent attack service. It can be started on demand, and provide a full audit log of what was done in a particular shell session.

A similar design can be accomplished in very few lines of Ruby, shell scripts, etc. but the reliance on a separate process to terminate the encrypted connection makes auditability cumbersome. Hence the desire for a single-purpose tool.

## Command line options
-authorized-keys=<filename>

Required must be in the authorized_keys format used by OpenSSH. Use - for stdin.
-port=<n>

Listen on the specified port number. Defaults to 2022.
-log=<filename>

If provided, write all input and output to the given file, creating a transcript of the shell session. Defaults to stdout.
-announce=<cmd>

If provided, the given command will be executed with a single argument, which will be the public key of the server in a format suitable for appending to an OpenSSH known_hosts file. For example: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbnqQ/SGC/OWnL4cQGxlZcFxxfCVx0mD+1MlF/Zdidu.
-timeout=<seconds>

If no successful happens with this time, print an error to stderr and exit with a zero status code. Default is 600 (10 minutes).