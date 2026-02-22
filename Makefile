#
# Makefile
#
# Simple makefile to build binary.
#
# @author Kubernetes Team <k8s_team@wayfair.com>
# @copyright 2019 Wayfair, LLC. -- All rights reserved.

VENDOR_DIR = vendor

.PHONY: get-deps
get-deps: $(VENDOR_DIR)

$(VENDOR_DIR):
	go generate $$(go list ./mocks/...)
	go mod download

.PHONY: build
build: $(VENDOR_DIR)
	GOOS=linux CGO_ENABLED=0 go build -a -ldflags '-extldflags "-static"' -o telefonistka ./cmd/telefonistka

.PHONY: clean
clean:
	rm -f telefonistka

.PHONY: test
test: $(VENDOR_DIR)
	go test -v -timeout 30s ./...

