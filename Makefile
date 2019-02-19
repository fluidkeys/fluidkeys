ifneq (${HOMEBREW_FORMULA_PREFIX},)
    PREFIX=${HOMEBREW_FORMULA_PREFIX}
else
    PREFIX?=/usr/local
endif


DEB=pkg/debian
SECRETS_ID_RSA=.secret/download-fluidkeys-com.id_rsa
MAIN_GO_FILES=cmd/fk/main.go
ALL_GO_FILES=$(shell find . -name '*.go')

# `make compile` should populate build/ with all files that will
# ultimately be installed to PREFIX (/usr/local), for example
# ./build/bin/fk, ./build/share etc
.PHONY: compile
compile: build/bin/fk


build/bin/fk: $(MAIN_GO_FILES) $(ALL_GO_FILES)
	go build -o $@ $(MAIN_GO_FILES)

.PHONY: test
test:
	go test ./...
	./script/test_lint
	./script/test_make_compile
	./script/test_make_install
	./script/test_dep_gopkg_files
	./script/test_discover_dbus_session_address

.PHONY: test_lint
test_lint:
	gometalinter --config .gometalinter.json ./...

.PHONY: run
run: $(MAIN_GO_FILES)
	go run $<

.PHONY: publish_latest_tag
publish_latest_tag: $(SECRETS_ID_RSA)
	./script/publish_latest_tag

.PHONY: release
release:
	./script/release

.PHONY: clean
clean:
	@rm -rf build
	@mkdir -p build

ifeq (${FLUIDKEYS_APT_ID_RSA},)
$(SECRETS_ID_RSA):
	@echo "FAIL: $@ missing and FLUIDKEYS_APT_ID_RSA not set"
	@/bin/false
else
$(SECRETS_ID_RSA): .secret
	cp "${FLUIDKEYS_APT_ID_RSA}" "$@"
endif

.secret:
	mkdir -p .secret

$(DEB)/usr/bin/fk: build/bin/fk
	@mkdir -p $(DEB)/usr/bin
	ln -f $< $@

.PHONY: homebrew_install
homebrew_install: install
	@echo 'NOTICE: `make homebrew_install` is deprecated, use `make install`'

.PHONY: install
install: compile
	@echo "Installing into $(PREFIX) (change with PREFIX=/some/directory)"
	@mkdir -p ${PREFIX}
	rsync -razv build/ ${PREFIX}
