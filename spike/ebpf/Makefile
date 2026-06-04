# S19a eBPF feasibility spike — build/run on a BTF-enabled Linux kernel ONLY.
#
# Requires: clang, llvm, libbpf headers (bpf/*.h), bpftool, Go 1.26, and CAP_BPF
# (or root) to load. This is throwaway de-risking code; it is NOT part of the
# probectl production build and is excluded from the repo's CI/lint.

CLANG   ?= clang
BPFTOOL ?= bpftool

.PHONY: help vmlinux generate build run clean

help:
	@echo "S19a eBPF spike — needs a BTF Linux kernel (>=5.8) + clang + Go + CAP_BPF."
	@echo "targets: vmlinux | generate | build | run | clean   (will NOT run on macOS/CI)"

# Reconstruct vmlinux.h from the running kernel's BTF (the CO-RE input).
vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h

# bpf2go: compile bpf/*.bpf.c (CO-RE, little-endian) + generate Go bindings.
generate: vmlinux
	go generate ./...

build: generate
	go build -o l4flow .

run: build
	sudo ./l4flow

clean:
	rm -f l4flow bpf/vmlinux.h l4flow_bpfel.go l4flow_bpfeb.go l4flow_bpfel.o l4flow_bpfeb.o
