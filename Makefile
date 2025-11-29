
CC = clang
CXX = clang++
AS = clang
LD = ld.lld
CARGO = cargo
OBJCOPY = llvm-objcopy

# --- Targets & Objects ---
TARGETS = flat loader flat.bin unit carrier
FLAT_OBJS = entry.o fifo.o magic.o elf.o lib/libc.a
UNIT_OBJS = unit.o fifo.o
# --- Flags ---
TARGET_ARCH = 
	
CFLAGS = -fPIC -c -O0 -g $(TARGET_ARCH)
ASFLAGS = -g -c $(TARGET_ARCH)
LDFLAGS = -T flat.ld -static -pie
RUST_SRCS := $(shell find src/rust -name "*.rs")

# --- Rules ---

all: $(TARGETS)
	./carrier test/ssh

flat: $(FLAT_OBJS)
	$(LD) $(LDFLAGS) -o flat $(FLAT_OBJS)

unit: $(UNIT_OBJS)
	$(CXX) $(UNIT_OBJS) -o unit

flat.bin: flat
	$(OBJCOPY) --set-section-flags .bss=contents,alloc,load \
        --gap-fill=0x00 \
        -O binary flat flat.bin

loader: src/c/loader.c
	$(CC) -o $@ $<

entry.o: src/asm/entry.S
	$(AS) $(ASFLAGS) -o $@ $<

magic.o: src/c/magic.c
	$(CC) $(CFLAGS) -o $@ $<

fifo.o: src/c/fifo.c
	$(CC) $(CFLAGS) -o $@ $<

elf.o: src/c/elf.c
	$(CC) $(CFLAGS) -o $@ $<

unit.o: src/cpp/unit.cpp
	$(CC) $(CFLAGS) -o $@ $<

carrier: $(RUST_SRCS)
	$(CARGO) build
	cp /tmp/rust-target/x86_64-unknown-linux-gnu/debug/carrier .

lib/libc.a: 
	cp /lib/musl/lib/libc.a lib/

clean:
	rm -f $(TARGETS) $(FLAT_OBJS) $(LOADER_OBJS) $(UNIT_OBJS)
	# cargo clean

.PHONY: all clean