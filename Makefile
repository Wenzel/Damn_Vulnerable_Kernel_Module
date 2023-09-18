obj-m = dvkm.o
KVERSION = $(shell uname -r)
KRN_SOURCES ?= /lib/modules/$(KVERSION)/build

.PHONY: all clean

all:
	make -C $(KRN_SOURCES) M=$(PWD) modules
clean:
	make -C $(KRN_SOURCES) M=$(PWD) clean
