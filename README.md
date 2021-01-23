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
2. The code must implement the command line options, process lifecycle, and error reporting described below. Stylistic differences (e.g. `--flag` instead of `-flag`) are fine.

## Example use case

When operating services in a managed container environment (e.g. Amazons Fargate) you may not have access to the host system running your container. In particular, it's often not possible to use `docker exec` to run a shell in the same environment that your service runs.

You can of course include or some other small SSH daemon in your image, but managing (and auditing) access to that brings more complexity. The design of `otssh` is such that it does not present any persistent attack service. It can be started on demand, and provide a full audit log of what was done in a particular shell session.

A similar design can be accomplished in very few lines of Ruby, shell scripts, etc. but the reliance on a separate process to terminate the encrypted connection makes auditability cumbersome. Hence the desire for a single-purpose tool.


## Command line options

### -authorized-keys=\<filename>

**Required** must be in the `authorized_keys` format used by OpenSSH. Use `-` for stdin.

### -port=\<n>

Listen on the specified port number. Defaults to `2022`.

### -log=\<filename>

If provided, write all input and output to the given file, creating a transcript of the shell session. Defaults to stdout.

### -announce=\<cmd>

If provided, the given command will be executed with a single argument, which will be the public key of the server in a format suitable for appending to an OpenSSH `known_hosts` file. For example: `ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIPbnqQ/SGC/OWnL4cQGxlZcFxxfCVx0mD+1MlF/Zdidu`.

### -timeout=\<seconds>

If no successful happens with this time, print an error to stderr and exit with a zero status code. Default is 600 (10 minutes).

## Process lifecycle

When you run `otssh` it goes through the following steps.

1. Loads authorized keys into memory.
2. Copies all environment variables.
3. Generates a new ed25519 keypair and prints the public key to STDOUT in the same format as `--announce`.
5. Opens the listening TCP socket.
4. Announces the public key and port. (see the `--announce` documentation above).
6. Accepts a connection on that socket.
7. Authenticates the connection using the provided authorized keys.
8. If authentication fails, closes the connection and returns to step 6.
9. Starts a login shell subprocess connected to the socket, using the current value of `$SHELL` with the full copied environment.
10. Waits for shell to exit.
11. Closes the port.
12. Exits with the exit code from step 9.

### Timeout

If no authenticated session begins before the global timeout the socket is torn down and the process exits succesfully.

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

Reported when the `-log` option is provided and does not refer to a writable destination.

## Additional Resources

Here is the Ruby script I currently use in concert with [`tinyssh`](https://tinyssh.org/):

```rb
require 'socket'

$stdout.sync = true

setup_thread = Thread.new do
  user_ssh_dir = File.join(Dir.home, '.ssh')
  Dir.mkdir(user_ssh_dir, 0o700) unless File.exist? user_ssh_dir
  authorized_keys_path = File.join(user_ssh_dir, 'authorized_keys')
  File.open(authorized_keys_path, 'w') do |f|
    f.write(File.read(ENV['AUTHORIZED_KEYS']))
    f.chmod(0o400)
  end

  File.open('/etc/profile.d/copyenv.sh', 'a') do |f|
    ENV.each do |k, v|
      next if %w[PWD USER].include?(k)

      f.write("export #{k}=\"#{v}\"\n")
    end
  end
end

server_thread = Thread.new do
  server_keydir = '/etc/tinyssh/sshkeydir'
  system("tinysshd-makekey #{server_keydir}")

  listener = TCPServer.open(2222)

  setup_thread.join

  puts "Host key: #{`tinysshd-printkey #{server_keydir}`}"
  puts 'Waiting for connection...'
  client = listener.accept
  puts "Connection from #{client.peeraddr(false)}"
  IO.popen("/usr/sbin/tinysshd #{server_keydir}", 'r+') do |sshd|
    thr = Thread.new { pump(sshd, client) }
    pump(client, sshd)
    thr.join
  end
end

def pump(from, to)
  loop do
    buffer = begin
      from.read_nonblock(4096)
    rescue IO::WaitReadable
      IO.select([from])
      retry
    rescue EOFError
      to.close_write
      break
    end

    while buffer.size.positive?
      begin
        wrote = to.write_nonblock(buffer)
        buffer = buffer[wrote..]
      rescue IO::WaitWritable
        IO.select(nil, [to])
        retry
      rescue EOFError
        from.close_read
        break
      end
    end
  end
end

server_thread.join
```

It seems like [this example](https://pkg.go.dev/golang.org/x/crypto/ssh#example-NewServerConn) from the documentation of the `golang.org/x/crypto/ssh` is pretty close to what I want already.
