NAME=dns
VERSION=$(version)
MAINTAINER="AdGuard Web Team"
USER="dns"
SHELL := /bin/bash

.PHONY: default
default: repo

GOPATH=$(shell pwd)/go_$(VERSION)

clean:
	rm -fv *.deb

build: check-vars clean
	mkdir -p $(GOPATH)
	GOPATH=$(GOPATH) go get -v -d github.com/AdguardTeam/AdguardDNS
	GOPATH=$(GOPATH) go get -v -d github.com/coredns/coredns
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
		-n adguard-$(NAME)-service \
		-m $(MAINTAINER) \
		--vendor $(MAINTAINER) \
		-C go_$(VERSION)/bin \
		coredns

repo: package
	/usr/local/bin/add_package_to_repo.sh $(NAME)_service $(VERSION) *.deb

check-vars:
ifndef version
	$(error VERSION is undefined)
endif
