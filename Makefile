CC      = $(CROSS)gcc
AR      = $(CROSS)ar
STRIP   = $(CROSS)strip
RANLIB  = $(CROSS)ranlib
LDFLAGS = $(EXLDFLAGS)
CFLAGS	= -O2 -Wall $(EXCFLAGS)

EXEC = libexc.a

all: $(EXEC)

libexc.a: ex_clib.o ex_clib.h
	$(AR) rc libexc.a ex_clib.o
	$(RANLIB) libexc.a

clean:
	-rm -f $(EXEC) *.elf *.gdb *.o

install:
