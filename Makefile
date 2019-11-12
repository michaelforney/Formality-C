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

clean:
	rm -f FM-Net/fm-net $(FM_NET_OBJ)
