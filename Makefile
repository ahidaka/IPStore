CC	= gcc
LD	= ld
COPTS   = -O2
CFLAGS	= -Wall $(COPTS)

all:	ipstore.o

ipstore.o:	ip_st_compat.o ipstore_core.o
	$(LD) -m elf_i386 -r -o ipstore.o ip_st_compat.o ipstore_core.o

.c.o:
	$(CC) -D__KERNEL__ -I/usr/src/linux-`uname -r`/include -Wall \
	 -Wstrict-prototypes -Wno-trigraphs -O2 -fno-strict-aliasing -fno-common \
	 -fomit-frame-pointer -pipe -mpreferred-stack-boundary=2 \
	 -march=i686 -DMODULE -DMODVERSIONS  \
	 -include /usr/src/linux-`uname -r`/include/linux/modversions.h \
	 -nostdinc -iwithprefix include -DKBUILD_BASENAME=ipstore  \
	 -c $<

clean:
	rm -f *.o *~ core
