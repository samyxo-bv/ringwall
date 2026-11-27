SHELL := /usr/bin/env bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
ARCH ?= $(shell uname -m | sed 's/x86_64/amd64/;s/aarch64/arm64/')
BPF_CLANG ?= clang
BPF_ARCH ?= $(shell uname -m | sed 's/x86_64/x86/;s/aarch64/arm64/')
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: all bpf build build-noebpf test vet clean iso test-iso

all: build

bpf:
	$(BPF_CLANG) -O2 -g -target bpf -D__TARGET_ARCH_$(BPF_ARCH) \
		-I/usr/include/$(shell uname -m)-linux-gnu \
		-c ebpf/ringwall.bpf.c -o internal/sensor/ringwall.bpf.o

build: bpf
	mkdir -p bin
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -mod=readonly -tags ebpf_embed -ldflags "$(LDFLAGS)" -o bin/ringwalld ./cmd/ringwalld
	CGO_ENABLED=0 GOOS=linux GOARCH=$(ARCH) go build -mod=readonly -ldflags "$(LDFLAGS)" -o bin/ringwallctl ./cmd/ringwallctl

build-noebpf:
	mkdir -p bin
	CGO_ENABLED=0 go build -mod=readonly -ldflags "$(LDFLAGS)" -o bin/ringwalld ./cmd/ringwalld
	CGO_ENABLED=0 go build -mod=readonly -ldflags "$(LDFLAGS)" -o bin/ringwallctl ./cmd/ringwallctl

test:
	go test -mod=readonly -race -v ./...

vet:
	go vet -mod=readonly ./...

iso: build
	sudo ./iso/build-iso.sh

test-iso:
	./iso/test-qemu.sh dist/ringwall-appliance-amd64.iso

clean:
	rm -rf bin dist internal/sensor/ringwall.bpf.o coverage.out
