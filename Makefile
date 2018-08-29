NAME=adguard-internal-dns
VERSION=$(version)
MAINTAINER="AdGuard Web Team"
USER="dns"
SHELL := /bin/bash

.PHONY: default
default: repo

GOPATH=$(shell pwd)/go_$(VERSION)

clean:
	rm -fv *.deb

## replace bit.adguard.com with github and remove ln -s once we push adguard-dns to github
build: check-vars clean
	mkdir -p $(GOPATH)
	GOPATH=$(GOPATH) go get -v -d -insecure bit.adguard.com/dns/adguard-dns
	GOPATH=$(GOPATH) go get -v -d github.com/coredns/coredns
	mkdir -p $(GOPATH)/src/github.com/AdguardTeam
	ln -s $(GOPATH)/src/bit.adguard.com/dns/adguard-dns $(GOPATH)/src/github.com/AdguardTeam/AdguardDNS
	cp plugin.cfg $(GOPATH)/src/github.com/coredns/coredns
	cd $(GOPATH)/src/github.com/coredns/coredns; GOPATH=$(GOPATH) go generate
	cd $(GOPATH)/src/github.com/coredns/coredns; GOPATH=$(GOPATH) go get -v -d -t .
	cd $(GOPATH)/src/github.com/coredns/coredns; GOPATH=$(GOPATH) PATH=$(GOPATH)/bin:$(PATH) make
	cd $(GOPATH)/src/github.com/coredns/coredns; GOPATH=$(GOPATH) go build -x -v -ldflags="-X github.com/coredns/coredns/coremain.GitCommit=$(VERSION)" -o $(GOPATH)/bin/coredns

package: build
	fpm --prefix /opt/$(NAME) \
		--deb-user $(USER) \
		--after-install postinstall.sh \
		--after-remove postrm.sh \
		--before-install preinstall.sh \
		--before-remove prerm.sh \
		--template-scripts \
		--template-value user=$(USER) \
		--template-value project=$(NAME) \
		--template-value version=1.$(VERSION) \
		--license proprietary \
		--url https://adguard.com/adguard-dns/overview.html \
		--category non-free/web \
		--description "AdGuard DNS (internal)" \
		--deb-no-default-config-files \
		-v 1.$(VERSION) \
		-s dir \
		-t deb \
		-n $(NAME) \
		-m $(MAINTAINER) \
		--vendor $(MAINTAINER) \
		-C go_$(VERSION)/bin \
		coredns

repo: package
	for package in *.deb ; do freight-add $$package apt/jessie/non-free ; done
	freight-cache

check-vars:
ifndef version
	$(error VERSION is undefined)
endif
