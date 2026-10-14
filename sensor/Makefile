# Provenza egress sensor.
#   make bpf        rebuild the kernel program (needs clang >= 14)
#   make build      the provenza-sensor binary (Go only; the program is embedded)
#   make test       unit tests; sudo make test-kernel loads it into this kernel
#   make install    install the binary and the systemd unit
#   make uninstall  detach kernel state and remove the cache
#   make clean      remove build artifacts

CLANG    ?= clang
BPF_OBJ  := internal/bpfobj/sensor.bpf.o
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
GOFLAGS  ?=
LDFLAGS  := -s -w -X main.version=$(VERSION)
PREFIX   ?= /usr/local
UNITDIR  ?= /etc/systemd/system
CONFIG   ?= /etc/provenza-sensor

.PHONY: all bpf build test test-kernel install uninstall clean vet

all: build

bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/sensor.bpf.c $(wildcard bpf/headers/*.h)
	$(CLANG) -O2 -g -Wall -Werror -fdebug-compilation-dir=. -ffile-prefix-map=$(CURDIR)=. -target bpf -I bpf/headers -c $< -o $@

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -trimpath -ldflags '$(LDFLAGS)' \
		-o provenza-sensor ./cmd/provenza-sensor

vet:
	go vet ./...

test: vet
	go test ./...

test-kernel:
	PROVENZA_SENSOR_KERNEL_TESTS=1 go test -count=1 -v ./internal/kerneltest/

install: build
	install -m 0755 provenza-sensor $(DESTDIR)$(PREFIX)/bin/provenza-sensor
	install -m 0644 packaging/provenzasensor.service $(DESTDIR)$(UNITDIR)/provenzasensor.service
	install -d -m 0755 $(DESTDIR)$(CONFIG)

uninstall:
	-./provenza-sensor --uninstall
	-rm -f $(DESTDIR)$(PREFIX)/bin/provenza-sensor
	-rm -f $(DESTDIR)$(UNITDIR)/provenzasensor.service

clean:
	rm -f provenza-sensor $(BPF_OBJ)
