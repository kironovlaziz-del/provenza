# Provenza egress sensor.
#   make bpf    rebuild the kernel program (needs clang >= 14)
#   make build  the provenza-sensor binary (Go only; the program is embedded)
#   make test   unit tests; `sudo make test-kernel` loads it into this kernel

CLANG ?= clang
BPF_OBJ := internal/bpfobj/sensor.bpf.o

.PHONY: bpf build test test-kernel

bpf: $(BPF_OBJ)

$(BPF_OBJ): bpf/sensor.bpf.c bpf/headers/*.h
	$(CLANG) -O2 -g -Wall -Werror -target bpf -I bpf/headers -c bpf/sensor.bpf.c -o $@

build:
	CGO_ENABLED=0 go build -trimpath -o provenza-sensor ./cmd/provenza-sensor

test:
	go vet ./...
	go test ./...

test-kernel:
	PROVENZA_SENSOR_KERNEL_TESTS=1 go test -count=1 -v ./internal/kerneltest/
