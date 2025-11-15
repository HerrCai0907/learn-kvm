#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

#include <stdint.h>
#include <stdio.h>
#include <string.h>

int main(int argc, char **argv) {
  int kvm_fd;
  if ((kvm_fd = open("/dev/kvm", O_RDWR)) < 0) {
    fprintf(stderr, "failed to open /dev/kvm: %d\n", errno);
    return 1;
  }

  int vm_fd;
  if ((vm_fd = ioctl(kvm_fd, KVM_CREATE_VM, 0)) < 0) {
    fprintf(stderr, "failed to create vm: %d\n", errno);
    return 1;
  }

  void *mem;
  if ((mem = mmap(NULL, 1 << 30, PROT_READ | PROT_WRITE,
                  MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0)) ==
      NULL) {
    fprintf(stderr, "mmap failed: %d\n", errno);
    return 1;
  }

  struct kvm_userspace_memory_region region;
  memset(&region, 0, sizeof(region));
  region.slot = 0;
  region.guest_phys_addr = 0;
  region.memory_size = 1 << 30;
  region.userspace_addr = (uintptr_t)mem;
  if (ioctl(vm_fd, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
    fprintf(stderr, "ioctl KVM_SET_USER_MEMORY_REGION failed: %d\n", errno);
    return 1;
  }

  {
    // load img
    int img_fd = open(argv[1], O_RDONLY);
    if (img_fd < 0) {
      fprintf(stderr, "can not open binary guest file: %d\n", errno);
      return 1;
    }
    char *p = (char *)mem;
    for (;;) {
      int r = read(img_fd, p, 4096);
      if (r <= 0) {
        break;
      }
      p += r;
    }
    close(img_fd);
  }

  int vcpu_fd;
  if ((vcpu_fd = ioctl(vm_fd, KVM_CREATE_VCPU, 0)) < 0) {
    fprintf(stderr, "can not create vcpu: %d\n", errno);
    return 1;
  }
  int kvm_run_mmap_size = ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (kvm_run_mmap_size < 0) {
    fprintf(stderr, "ioctl KVM_GET_VCPU_MMAP_SIZE: %d\n", errno);
    return 1;
  }
  struct kvm_run *run = (struct kvm_run *)mmap(
      NULL, kvm_run_mmap_size, PROT_READ | PROT_WRITE, MAP_SHARED, vcpu_fd, 0);
  if (run == NULL) {
    fprintf(stderr, "mmap kvm_run: %d\n", errno);
    return 1;
  }

  struct kvm_sregs sregs;
  if (ioctl(vcpu_fd, KVM_GET_SREGS, &sregs) < 0) {
    perror("can not get sregs\n");
    return 1;
  }

  sregs.cs.base = 0;
  sregs.cs.selector = 0;
  sregs.ds.base = 0;
  sregs.ds.selector = 0;
  sregs.es.base = 0;
  sregs.es.selector = 0;
  sregs.fs.base = 0;
  sregs.fs.selector = 0;
  sregs.gs.base = 0;
  sregs.gs.selector = 0;

  if (ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
    perror("can not set sregs");
    return 1;
  }

  struct kvm_regs regs;
  regs.rflags = 2;

  regs.rip = 0;
  regs.rsp = 0x00000000000ff000;

  regs.rax = 0x0000000000000006;
  regs.rbp = 0x10;
  regs.rdi = 0x21;
  if (ioctl(vcpu_fd, KVM_SET_REGS, &(regs)) < 0) {
    perror("KVM SET REGS\n");
    return 1;
  }

  int ret = ioctl(vcpu_fd, KVM_RUN, 0);
  if (ret < 0) {
    fprintf(stderr, "KVM_RUN failed\n");
    return 1;
  }
  switch (run->exit_reason) {
  case KVM_EXIT_IO:
    printf("IO port: %x, data: %x\n", run->io.port,
           *(int *)((char *)(run) + run->io.data_offset));
    break;
  case KVM_EXIT_SHUTDOWN:
    goto exit;
  }

exit:
  return 0;
}
