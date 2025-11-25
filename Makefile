
CC = clang
AS = clang
LD = ld.lld
OBJCOPY = llvm-objcopy

# --- Targets & Objects ---
TARGETS = flat loader
FLAT_OBJS = entry.o embedded.o

# --- Flags ---
TARGET_ARCH = 

CFLAGS = -fPIC -c -Og -g $(TARGET_ARCH)
ASFLAGS = -g -c $(TARGET_ARCH)
LDFLAGS = -T flat.ld -static -pie

# --- Rules ---

all: $(TARGETS)
	$(OBJCOPY) --set-section-flags .bss=contents,alloc,load \
        --gap-fill=0x00 \
        -O binary flat flat.bin

flat: $(FLAT_OBJS)
	$(LD) $(LDFLAGS) -o flat $(FLAT_OBJS) lib/libc.a

loader:
	$(CC) src/loader.c -o loader

entry.o: src/asm/entry.S
	$(AS) $(ASFLAGS) -o $@ $<

embedded.o: src/embedded.c
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm -f $(TARGETS) $(FLAT_OBJS) $(LOADER_OBJS) flat.bin

.PHONY: all clean