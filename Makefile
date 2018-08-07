hello-gpg: hello-gpg.go
	go build $<

.PHONY: run
run: hello-gpg.go
	go run $<
