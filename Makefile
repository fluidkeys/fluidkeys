build/bin/fk: fluidkeys.go
	@mkdir -p build/bin
	go build -o $@ $<

.PHONY: run
run: fluidkeys.go
	go run $<
