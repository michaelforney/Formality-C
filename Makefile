.POSIX:
.PHONY: all clean

CFLAGS+=-pedantic -Wall
LDLIBS=-lm

all: FM-Net/fm-net

clean:
	rm -f FM-Net/fm-net
