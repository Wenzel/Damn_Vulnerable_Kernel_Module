# Kernel module name
obj-m := dvkm.o

# Kernel version and build directory
KVERSION  := $(shell uname -r)
KRN_SOURCES ?= /lib/modules/$(KVERSION)/build

# flags
CFLAGS   += -Wall -Wextra

# Output binary for the userland test program
TEST_BIN := test_dvkm
TEST_SRC := test_dvkm.c

# Phony targets
.PHONY: all clean module user

# Default target
all: module user

# Build the kernel module
module:
	$(MAKE) -C $(KRN_SOURCES) M=$(CURDIR) modules

# Build the userland test binary
user: $(TEST_BIN)

$(TEST_BIN): $(TEST_SRC)
	$(CC) $(CFLAGS) -I$(KRN_SOURCES)/arch/x86/include $< -o $@

# Clean both kernel module and test binary
clean:
	$(MAKE) -C $(KRN_SOURCES) M=$(CURDIR) clean
	$(RM) $(TEST_BIN)
