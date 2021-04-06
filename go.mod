module otssh

go 1.13

require (
	github.com/creack/pty v1.1.11
	github.com/mikesmitty/edkey v0.0.0-20170222072505-3356ea4e686a
	github.com/rendon/testcli v1.0.1-0.20210403221206-70ecfa5dbedf
	github.com/urfave/cli/v2 v2.3.0
	golang.org/x/crypto v0.0.0-20201221181555-eec23a3978ad
	golang.org/x/term v0.0.0-20201210144234-2321bbc49cbf // indirect
)

replace github.com/rendon/testcli => github.com/gerbyzation/testcli v1.0.1-0.20210409211032-f46e329c6005
