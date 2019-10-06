
obj-m += new.o
KVERSION = $(shell uname -r)
VERSION = v1.1
CC = gcc



all:
	make -C /lib/modules/$(KVERSION)/build M=$(PWD) modules
	rm -rf *.c~
	rm -rf *.mod*
	rm -rf *.o
clean:
	make -C /lib/modules/$(KVERSION/build M=$(PWD) clean


