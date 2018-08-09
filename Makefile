DEB=pkg/debian
SECRETS_ID_RSA=.secret/download-fluidkeys-com.id_rsa

.PHONY: compile
compile: build/bin/fk

build/bin/fk: src/fluidkeys.go
	@mkdir -p build/bin
	go build -o $@ $<

.PHONY: run
run: src/fluidkeys.go
	go run $<

.PHONY: publish_tag
publish_tag: $(DEB)/DEBIAN/md5sums $(SECRETS_ID_RSA)
	@mkdir -p pkg/out
	./script/publish_tag

.PHONY: release
release:
	./script/release

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

$(DEB)/DEBIAN/md5sums: $(DEB)/usr/bin/fk
	cd $(DEB) ; \
	find . -type f ! -regex '.*.hg.*' ! -regex '.*?debian-binary.*' ! -regex '.*?DEBIAN.*' -printf '%P ' | xargs md5sum > DEBIAN/md5sums
	
$(DEB)/usr/bin/fk: build/bin/fk
	@mkdir -p $(DEB)/usr/bin
	ln -f $< $@

.PHONY: homebrew_install
homebrew_install: compile
	@mkdir -p ${HOMEBREW_FORMULA_PREFIX}/bin
	cp build/bin/fk ${HOMEBREW_FORMULA_PREFIX}/bin/fk
