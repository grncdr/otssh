test:
	go build -o tests/otssh main.go && go test tests/e2e_test.go -v