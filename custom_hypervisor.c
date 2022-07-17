#include <stdio.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <stdint.h>
#include <linux/kvm.h>

#define printfdebug(...) printf("\033[0;31m" "DEBUG: " "\033[0m" __VA_ARGS__)

const uint8_t code[] = {
	0xba, 0xf8, 0x03, /* mov $0x3f8, %dx */
	0x00, 0xd8,       /* add %bl, %al */
	0x04, '0',        /* add $'0', %al */
	0xee,             /* out %al, (%dx) */
	0xb0, '\n',       /* mov $'\n', %al */
	0xee,             /* out %al, (%dx) */
	0xf4,             /* hlt */
};

struct vm {
	int sys_fd;
	int fd;
	char *mem;
};

int main(){
	
	struct vm vm;

	/* 
	We need read-write access to the device to set up a virtual machine, 
	and all opens not explicitly intended for inheritance across exec should use O_CLOEXEC.
	*/
	vm.sys_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);

	/*
	Out application should first confirm that it has version 12, via the KVM_GET_API_VERSION ioctl():
	The argument fd must be an open file descriptor.
    The second argument is a device-dependent request code.
	The third argument is an untyped pointer to memory.
	*/

	int ret = ioctl(vm.sys_fd, KVM_GET_API_VERSION, NULL);
    
	if (ret == -1){
		printf("%d", ret);
		err(1, "KVM_GET_API_VERSION");
	}
    if (ret != 12)
		errx(1, "KVM_GET_API_VERSION %d, expected 12", ret);

	/*
	After checking the version, we will check for extensions we are using, using the KVM_CHECK_EXTENSION ioctl(). 
	However, for extensions that add new ioctl() calls, we can generally just call the ioctl(), 
	which will fail with an error (ENOTTY) if it does not exist.
	In this program we check for the one extension we use, 
	KVM_CAP_USER_MEM (required to set up guest memory via the KVM_SET_USER_MEMORY_REGION ioctl())
	*/

	ret = ioctl(vm.sys_fd, KVM_CHECK_EXTENSION, KVM_CAP_USER_MEMORY);
    if (ret == -1)
		err(1, "KVM_CHECK_EXTENSION");
    if (!ret)
		errx(1, "Required extension KVM_CAP_USER_MEM not available");

	/*
	We need to create a virtual machine (VM), 
	which represents everything associated with one emulated system, 
	including memory and one or more CPUs. 
	KVM gives us a handle to this VM in the form of a file descriptor
	*/
    vm.fd = ioctl(vm.sys_fd, KVM_CREATE_VM, (unsigned long)0);


	/*
	The VM will need some memory, which we provide in pages. 
	This corresponds to the "physical" address space as seen by the VM. 
	For performance, we wouldn't want to trap every memory access and emulate it by returning the corresponding data; 
	instead, when a virtual CPU attempts to access memory, 
	the hardware virtualization for that CPU will first try to satisfy that access via the memory pages we've configured. 
	If that fails (due to the VM accessing a "physical" address without memory mapped to it), 
	the kernel will then let the user of the KVM API handle the access, 
	such as by emulating a memory-mapped I/O device or generating a fault.

	we'll allocate a single page of memory to hold our code, using mmap() directly to obtain page-aligned zero-initialized memory:

	void * mmap (void *address, size_t length, int protect, int flags, int filedes,off_t offset)

	address	- This argument gives a preferred starting address for the mapping. 
			  If another mapping does not exist there, then the kernel will pick a nearby page boundary and create the mapping; 
			  otherwise, the kernel picks a new address. If this argument is NULL, then the kernel can place the mapping anywhere it sees fit.
	
	length	- This is the number of bytes which to be mapped.

	protect - This argument is used to control what kind of access is permitted. 
			  This argument may be logical ‘OR’ of the following flags PROT_READ | PROT_WRITE | PROT_EXEC | PROT_NONE.  
			  The access types of read, write and execute are the permissions on the content.

	flags	- This argument is used to control the nature of the map.
			  
			  MAP_SHARED: This flag is used to share the mapping with all other processes, which are mapped to this object. 
			  Changes made to the mapping region will be written back to the file.

			  MAP_ANONYMOUS / MAP_ANON: This flag is used to create an anonymous mapping. 
			  Anonymous mapping means the mapping is not connected to any files. 
			  This mapping is used as the basic primitive to extend the heap.
	
	filedes	- This is the file descriptor which has to be mapped.

	offset	- This is offset from where the file mapping started. 
			  In simple terms, the mapping connects to (offset) to (offset+length-1) bytes for the file open on filedes descriptor.

	*/

	// NOTE: Guest memory is allocated from the below line of the host OS
	vm.mem = mmap(NULL, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED | MAP_ANONYMOUS, -1, 0);
	printfdebug("Size of the guest memory = %zu\n", 0x1000);
	// NOTE: "vm->mem" is a pointer to the host's virtual memory to a block of memory
    //       of size equal to "0x1000"
	printfdebug("Virtual address space of the hypervisor at which 'vm.mem' is mapped = %p\n", (void *) vm.mem);


	/*
	Tell the KVM virtual machine about its spacious new 4096-byte memory
	
	The slot field provides an integer index identifying each region of memory we hand to KVM; 
	calling KVM_SET_USER_MEMORY_REGION again with the same slot will replace this mapping, 
	while calling it with a new slot will create a separate mapping. 
	
	guest_phys_addr specifies the base "physical" address as seen from the guest. 
	
	userspace_addr points to the backing memory in our process that we allocated with mmap(); 
	note that these always use 64-bit values, even on 32-bit platforms. 
	
	memory_size specifies how much memory to map: one page, 0x1000 bytes.
	*/

    struct kvm_userspace_memory_region region = {
	.slot = 0,
	.guest_phys_addr = 0x1000,
	.memory_size = 0x1000,
	.userspace_addr = (unsigned long)vm.mem,
    };

    ioctl(vm.fd, KVM_SET_USER_MEMORY_REGION, &region);

	memcpy(vm.mem, code, sizeof(code));

	/*
	A KVM virtual CPU represents the state of one emulated CPU, 
	including processor registers and other execution state. 
	Again, KVM gives us a handle to this VCPU in the form of a file descriptor

	The 0 here represents a sequential virtual CPU index.
	*/
	int vcpufd = ioctl(vm.fd, KVM_CREATE_VCPU, (unsigned long)0);


	/*
	We need to know how much memory to map, which KVM tells us with the KVM_GET_VCPU_MMAP_SIZE ioctl()
	*/
	int mmap_size = ioctl(vm.sys_fd, KVM_GET_VCPU_MMAP_SIZE, NULL);

	/*
	Now that we have the size, we can mmap() the kvm_run structure:
	*/

	// NOTE: The below line allocates a small portion of VCPU runtime memory from
    //               the host OS to store the information it has to exchange with KVM.
	struct kvm_run *run = mmap(NULL, mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpufd, 0);

	printfdebug("VCPU 'mmap_size' = %d\n", mmap_size);
    printfdebug("VCPU runtime memory location in virutal address space of the hypervisor = %p\n", run);

	struct kvm_sregs sregs;


	ioctl(vcpufd, KVM_GET_SREGS, &sregs);
    sregs.cs.base = 0;
    sregs.cs.selector = 0;
    ioctl(vcpufd, KVM_SET_SREGS, &sregs);

	struct kvm_regs regs = {
	.rip = 0x1000,
	.rax = 2,
	.rbx = 2,
	.rflags = 0x2,
    };
    ioctl(vcpufd, KVM_SET_REGS, &regs);

	
	while (1) {
		ioctl(vcpufd, KVM_RUN, NULL);


		switch (run->exit_reason) {
			case KVM_EXIT_HLT:
				puts("KVM_EXIT_HLT");
				return 0;

			case KVM_EXIT_IO:
				if (run->io.direction == KVM_EXIT_IO_OUT &&
					run->io.size == 1 &&
					run->io.port == 0x3f8 &&
					run->io.count == 1)
					putchar(*(((char *)run) + run->io.data_offset));
				else
					errx(1, "unhandled KVM_EXIT_IO");
				break;

			case KVM_EXIT_FAIL_ENTRY:
				errx(1, "KVM_EXIT_FAIL_ENTRY: hardware_entry_failure_reason = 0x%llx",
				 (unsigned long long)run->fail_entry.hardware_entry_failure_reason);

		}
    }


}