ifneq (${HOMEBREW_FORMULA_PREFIX},)
    PREFIX=${HOMEBREW_FORMULA_PREFIX}
else
    PREFIX?=/usr/local
endif


DEB=pkg/debian
SECRETS_ID_RSA=.secret/download-fluidkeys-com.id_rsa

# `make compile` should populate build/ with all files that will
# ultimately be installed to PREFIX (/usr/local), for example
# ./build/bin/fk, ./build/share etc
.PHONY: compile
compile: clean build/bin/fk

build/bin/fk: src/fluidkeys.go
	@mkdir -p build/bin
	go build -o $@ $<

.PHONY: run
run: src/fluidkeys.go
	go run $<

.PHONY: publish_tag
publish_tag: $(SECRETS_ID_RSA)
	./script/publish_tag

.PHONY: release
release:
	./script/release

.PHONY: clean
clean:
	rm -rf build
	mkdir -p build

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
	@echo "Installing following files to $(PREFIX) (change with PREFIX=/some/directory)"
	@tree build
	rsync -razv build/ ${PREFIX}
