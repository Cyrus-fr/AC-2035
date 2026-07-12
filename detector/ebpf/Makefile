# AC-2035 eBPF honeytoken detector — build config.
#
# Builds honeytoken_watch.c → honeytoken_watch.o (CO-RE) with clang + libbpf.
# Linux only; requires: clang (>=12), llvm, libbpf-dev, bpftool, and a kernel
# built with BTF (/sys/kernel/btf/vmlinux) for the `vmlinux` target.
#
#   make vmlinux   # generate vmlinux.h from the running kernel's BTF
#   make all       # compile the eBPF object
#   make clean     # remove build artifacts

CLANG   ?= clang
BPFTOOL ?= bpftool
ARCH    ?= x86

TARGET   := honeytoken_watch
SRC      := $(TARGET).c
OBJ      := $(TARGET).o
VMLINUX  := vmlinux.h

CFLAGS := -g -O2 -target bpf \
	-D__TARGET_ARCH_$(ARCH) \
	-I/usr/include/x86_64-linux-gnu \
	-I.

.PHONY: all clean vmlinux

all: $(OBJ)

# Generate BTF type info for CO-RE. Regenerate on a new kernel.
$(VMLINUX):
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $(VMLINUX)

vmlinux: $(VMLINUX)

$(OBJ): $(SRC) $(VMLINUX)
	$(CLANG) $(CFLAGS) -c $(SRC) -o $(OBJ)
	@echo "Built $(OBJ)"

clean:
	rm -f $(OBJ) $(VMLINUX)
