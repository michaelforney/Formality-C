.POSIX:
.PHONY: all clean

CFLAGS+=-pedantic -Wall
LDLIBS=-lm

FM_NET_OBJ=\
	FM-Net/main.o\
	FM-Net/fm-net.o

all: FM-Net/fm-net

$(FM_NET_OBJ): FM-Net/fm-net.h

FM-Net/fm-net: $(FM_NET_OBJ)

FM-Net/fm-net.wasm: FM-Net/fm-net.c
	clang --target=wasm32 -nostdlib -Wl,--no-entry -Wl,--export-all $(CFLAGS) -o $@ $<

clean:
	rm -f FM-Net/fm-net FM-Net/fm-net.wasm $(FM_NET_OBJ)
