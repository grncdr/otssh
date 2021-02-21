test:
	go build -o otssh main.go && go test e2e_test.go -v