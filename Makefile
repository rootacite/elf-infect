
CC = clang
AS = clang
LD = ld.lld
CARGO = cargo
OBJCOPY = llvm-objcopy

# --- Targets & Objects ---
TARGETS = flat loader carrier flat.bin
FLAT_OBJS = entry.o embedded.o

# --- Flags ---
TARGET_ARCH = 
	
CFLAGS = -fPIC -c -O0 -g $(TARGET_ARCH)
ASFLAGS = -g -c $(TARGET_ARCH)
LDFLAGS = -T flat.ld -static -pie
RUST_SRCS := $(shell find src/rust -name "*.rs")

# --- Rules ---

all: $(TARGETS)
	

flat: $(FLAT_OBJS)
	$(LD) $(LDFLAGS) -o flat $(FLAT_OBJS) lib/libc.a

flat.bin: flat
	$(OBJCOPY) --set-section-flags .bss=contents,alloc,load \
        --gap-fill=0x00 \
        -O binary flat flat.bin

loader: src/c/loader.c
	$(CC) -o $@ $<

entry.o: src/asm/entry.S
	$(AS) $(ASFLAGS) -o $@ $<

embedded.o: src/c/embedded.c
	$(CC) $(CFLAGS) -o $@ $<

carrier: $(RUST_SRCS)
	$(CARGO) build
	cp /tmp/rust-target/x86_64-unknown-linux-gnu/debug/carrier .

clean:
	rm -f $(TARGETS) $(FLAT_OBJS) $(LOADER_OBJS)
	cargo clean

.PHONY: all clean