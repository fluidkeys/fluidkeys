DEB=pkg/debian

build/bin/fk: src/fluidkeys.go
	@mkdir -p build/bin
	go build -o $@ $<

.PHONY: run
run: src/fluidkeys.go
	go run $<

.PHONY: deb
deb: $(DEB)/DEBIAN/md5sums
	@mkdir -p pkg/out
	dpkg -b $(DEB) pkg/out/fluidkeys_0.0.1_amd64.deb

$(DEB)/DEBIAN/md5sums: $(DEB)/usr/bin/fk
	cd $(DEB) ; \
	find . -type f ! -regex '.*.hg.*' ! -regex '.*?debian-binary.*' ! -regex '.*?DEBIAN.*' -printf '%P ' | xargs md5sum > DEBIAN/md5sums
	
$(DEB)/usr/bin/fk: build/bin/fk
	@mkdir -p $(DEB)/usr/bin
	ln -f $< $@
