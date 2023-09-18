/*
Test program for DVKM
Change IOCTL and params as per your needs.
Author: Hardik Shah, @hardik05
Email: hardik05@gmail.com
Web: http://hardik05.wordpress.com
*/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <stdbool.h>
#include <sys/mman.h>

#include <asm/nyx_api.h>

//Magic Codes
#define DVKM_IOCTL_MAGIC ('D')
#define IOCTL(NUM) _IOWR(DVKM_IOCTL_MAGIC, NUM, struct dvkm_obj)

//Vulnerabilities
#define DVKM_IOCTL_INTEGER_OVERFLOW IOCTL(0x0)
#define DVKM_IOCTL_INTEGER_UNDERFLOW IOCTL(0x1)
#define DVKM_IOCTL_STACK_BUFFER_OVERFLOW IOCTL(0x2)
#define DVKM_IOCTL_HEAP_BUFFER_OVERFLOW IOCTL(0x3)
/*#define DVKM_IOCTL_DIVIDE_BY_ZERO IOCTL(0x4)
#define DVKM_IOCTL_STACK_OOBR IOCTL(0x5)
#define DVKM_IOCTL_STACK_OOBW IOCTL(0x6)
#define DVKM_IOCTL_HEAP_OOBR IOCTL(0x7)
#define DVKM_IOCTL_HEAP_OOBW IOCTL(0x8)
#define DVKM_IOCTL_MEMORY_LEAK IOCTL(0x9)
#define DVKM_IOCTL_USE_AFTER_FREE IOCTL(0xA)
#define DVKM_IOCTL_USE_DOUBLE_FREE IOCTL(0xB)
#define DVKM_IOCTL_NULL_POINTER_DEREFRENCE IOCTL(0xC)
*/

struct dvkm_obj {
	int width;
	int height;
	int datasize;
	char *data;
} io_buffer = { 0 };

static int detectranges(char *mapfile, char *pattern)
{
	int ret = 0;
	char line[4096];

	if (!mapfile || !pattern) {
		return -1;
	}

	FILE *fp = fopen(mapfile, "r");
	if (!fp) {
		habort("failed to open mapfile\n");
	}

	while ((fgets(line, sizeof(line), fp) == line)) {
		unsigned long start = 0;
		unsigned long end = 0;

		// fields
		char module_name[64] = { 0 };
		unsigned long module_size = 0;
		int instances_loaded = 0;
		char load_state[32] = { 0 };
		unsigned long kernel_offset = 0;

		// dvkm 24576 0 - Live 0xffffffffc0201000 (O)
		ret = sscanf(line,
		             "%s %lu %d - %s %lx",
		             module_name,
		             &module_size,
		             &instances_loaded,
		             load_state,
		             &kernel_offset);
		start = kernel_offset;
		end = start + module_size;

		if (ret == 5) {
			if (strstr(module_name, pattern)) {
				hprintf("=> submit range %lx-%lx (%s)\n", start, end, module_name);
				// submit ranges
				uint64_t buffer[3] = { 0 };
				buffer[0] = start; // low range
				buffer[1] = end;   // high range
				buffer[2] = 0;     // IP filter index [0-3]
				kAFL_hypercall(HYPERCALL_KAFL_RANGE_SUBMIT, (uint64_t)buffer);
				fclose(fp);
				return 0;
			}
		}
	}
	habort("failed to locate dvkm in /proc/modules\n");
	return 0;
}

kAFL_payload *kafl_agent_init(bool verbose)
{
	host_config_t host_config = { 0 };

	hprintf("Initialize kAFL agent\n");
	// set ready state
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	// filters
	kAFL_hypercall(HYPERCALL_KAFL_SUBMIT_CR3, 0);
	kAFL_hypercall(HYPERCALL_KAFL_USER_SUBMIT_MODE, KAFL_MODE_64);

	kAFL_hypercall(HYPERCALL_KAFL_GET_HOST_CONFIG, (uintptr_t)&host_config);

	if (verbose) {
		hprintf("GET_HOST_CONFIG\n");
		hprintf("\thost magic:  0x%x, version: 0x%x\n",
		        host_config.host_magic,
		        host_config.host_version);
		hprintf("\tbitmap size: 0x%x, ijon:    0x%x\n",
		        host_config.bitmap_size,
		        host_config.ijon_bitmap_size);
		hprintf("\tpayload size: %u KB\n", host_config.payload_buffer_size / 1024);
		hprintf("\tworker id: %d\n", host_config.worker_id);
	}

	if (host_config.host_magic != NYX_HOST_MAGIC) {
		hprintf("HOST_MAGIC mismatch: %08x != %08x\n", host_config.host_magic, NYX_HOST_MAGIC);
		habort("HOST_MAGIC mismatch!");
	}

	if (host_config.host_version != NYX_HOST_VERSION) {
		hprintf("HOST_VERSION mismatch: %08x != %08x\n",
		        host_config.host_version,
		        NYX_HOST_VERSION);
		habort("HOST_VERSION mismatch!");
	}

	// if (host_config.payload_buffer_size > PAYLOAD_MAX_SIZE) {
	// 	hprintf("Fuzzer payload size too large: %lu > %lu\n",
	// 		host_config.payload_buffer_size, PAYLOAD_MAX_SIZE);
	// 	habort("Host payload size too large!");
	// 	return -1;
	// }

	agent_config_t agent_config = { 0 };
	agent_config.agent_magic = NYX_AGENT_MAGIC;
	agent_config.agent_version = NYX_AGENT_VERSION;
	//agent_config.agent_timeout_detection = 0; // timeout by host
	//agent_config.agent_tracing = 0; // trace by host
	//agent_config.agent_ijon_tracing = 0; // no IJON
	agent_config.agent_non_reload_mode = 0; // no persistent mode
	//agent_config.trace_buffer_vaddr = 0xdeadbeef;
	//agent_config.ijon_trace_buffer_vaddr = 0xdeadbeef;
	agent_config.coverage_bitmap_size = host_config.bitmap_size;
	//agent_config.input_buffer_size;
	//agent_config.dump_payloads; // set by hypervisor (??)

	kAFL_hypercall(HYPERCALL_KAFL_SET_AGENT_CONFIG, (uintptr_t)&agent_config);

	kAFL_payload *payload_buffer =
	    aligned_alloc((size_t)sysconf(_SC_PAGESIZE), host_config.payload_buffer_size);
	if (!payload_buffer) {
		habort("failed to allocate payload buffer !\n");
	}

	// ensure in resident memory
	mlock(payload_buffer, host_config.payload_buffer_size);
	// ↔️ mmap shared buffer between QEMU and the fuzzer
	kAFL_hypercall(HYPERCALL_KAFL_GET_PAYLOAD, (uintptr_t)payload_buffer);

	detectranges("/proc/modules", "dvkm");

	return payload_buffer;
}

int main()
{
	int fd;
	unsigned long ioctl_code, ioctl_num;

	kAFL_payload *payload_buffer = kafl_agent_init(false);
	fprintf(stderr, "\nOpening Driver\n");
	fd = open("/proc/dvkm", O_RDWR);
	if (fd < 0) {
		fprintf(stderr, "Cannot open device file...\n");
		return 0;
	}

	kAFL_hypercall(HYPERCALL_KAFL_NEXT_PAYLOAD, 0);
	// prepare ioctl code and io_buffer struct range[0-0xC]
	ioctl_code = payload_buffer->data[0] % 0xD;
	ioctl_num = IOCTL(ioctl_code);
	// write width, height and datasize
	size_t write_size = sizeof(struct dvkm_obj) - sizeof(io_buffer.data);
	memcpy((void *)&io_buffer, &payload_buffer[1], write_size);
	// assign rest of payload_buffer to io_buffer.data
	io_buffer.data = (char *)&payload_buffer->data[write_size + 1];
	// struct is now ready
	kAFL_hypercall(HYPERCALL_KAFL_ACQUIRE, 0);
	ioctl(fd, ioctl_num, &io_buffer);
	kAFL_hypercall(HYPERCALL_KAFL_RELEASE, 0);

	printf("Closing Driver\n");
	close(fd);
}
