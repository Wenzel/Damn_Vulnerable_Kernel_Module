obj-m = dvkm.o
KVERSION = $(shell uname -r)
KRN_SOURCES ?= /lib/modules/$(KVERSION)/build
CFLAGS := -Wall -Wextra
TARGET := $(obj-m) test_dvkm

.PHONY: all clean

all: $(TARGET)

$(obj-m): dvkm.c
	make -C $(KRN_SOURCES) M=$(PWD) modules

test_dvkm: test_dvkm.c
	$(CC) $(CFLAGS) -I ${KRN_SOURCES}/arch/x86/include $< -o $@

clean:
	make -C $(KRN_SOURCES) M=$(PWD) clean
	rm -f test_dvkm
