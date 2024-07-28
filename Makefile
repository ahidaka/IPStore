# 

TARGET:= ipstore.ko

all: ${TARGET}

ipstore.ko: ip_st_compat.c  ipsimple_core.h  ipstore_core.c
	make -C /usr/src/linux-`uname -r` M=`pwd` V=1 modules

clean:
	make -C /usr/src/linux-`uname -r` M=`pwd` V=1 clean

obj-m:= ipstore.o

ipstore-objs := ip_st_compat.o ipstore_core.o

clean-files := *.o *.ko *.mod.[co] *~
