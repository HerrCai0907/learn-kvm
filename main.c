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

typedef struct {
  uint16_t limit_low; // 段限长低16位
  uint16_t base_low;  // 基地址低16位
  uint8_t base_mid;   // 基地址中8位

  // 访问位（与虚拟内存一起使用）
  uint8_t access_bit : 1;
  // 可读可写
  //    0：只读（数据段）；只执行（代码段）
  //    1：读写（数据段）；读执行（代码段）
  uint8_t readable_and_writable : 1;
  // 扩展方向（数据段），符合（代码段）
  uint8_t expansion_direction : 1;
  // 可执行段
  //    0：数据段
  //    1：代码段
  uint8_t executable_segment : 1;

  // 描述符位
  //    0：系统描述符
  //    1：代码或数据描述符
  uint8_t descriptor_bit : 1;

  // 描述符特权级别 (DPL)
  //    0：（环 0）最高(内核)
  //    3：（环 3）最低(用户应用程序)
  uint8_t descriptor_privilege_level : 2;

  // 段是否在内存中（与虚拟内存一起使用）
  uint8_t segment_is_in_memory : 1;

  uint8_t limit_high : 4;
  uint8_t reserved_for_os : 1;
  uint8_t reserved : 1;

  // 0: 16 bit
  // 1: 32 bit
  uint8_t segment_type : 1;
  // 0: None
  // 1: limit * 4K
  uint8_t granularity : 1;

  uint8_t base_high; // 基地址高8位
} __attribute__((packed)) gdt_entry_t;

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

  gdt_entry_t *gdt_entry = (gdt_entry_t *)mem;
  memset(&gdt_entry[0], 0, sizeof(gdt_entry_t)); // 根据要求，第一个 gdt 为空
  gdt_entry[1] = (gdt_entry_t){
      .limit_low = 0xFFFF,
      .base_low = 0x0000,
      .base_mid = 0x00,
      .access_bit = 0,
      .readable_and_writable = 1,
      .expansion_direction = 0,
      .executable_segment = 1,
      .descriptor_bit = 1,
      .descriptor_privilege_level = 0,
      .segment_is_in_memory = 1,
      .limit_high = 0x0F,
      .reserved_for_os = 0,
      .reserved = 0,
      .segment_type = 1,
      .granularity = 1,
      .base_high = 0x00,
  };
  gdt_entry[2] = (gdt_entry_t){
      .limit_low = 0xFFFF,
      .base_low = 0x0000,
      .base_mid = 0x00,
      .access_bit = 0,
      .readable_and_writable = 1,
      .expansion_direction = 0,
      .executable_segment = 0,
      .descriptor_bit = 1,
      .descriptor_privilege_level = 0,
      .segment_is_in_memory = 1,
      .limit_high = 0x0F,
      .reserved_for_os = 0,
      .reserved = 0,
      .segment_type = 1,
      .granularity = 1,
      .base_high = 0x00,
  };

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

  sregs.gdt.base = 0;
  sregs.gdt.limit = 24 - 1;

  sregs.cr0 |= 1; // enable PE

  const int32_t gdt_index = 1;
  const gdt_entry_t *gdt = &gdt_entry[gdt_index];
  sregs.cs.base = (uint32_t)gdt->base_low | ((uint32_t)gdt->base_mid << 16) |
                  ((uint32_t)gdt->base_high << 24);
  sregs.cs.limit = ((uint32_t)gdt->limit_low | (gdt->limit_high << 16) + 1U) *
                       (gdt_entry[1].granularity == 1U ? 4096U : 1U) -
                   1U;
  sregs.cs.selector = 8 * gdt_index;
  sregs.cs.type = (gdt->executable_segment << 3) |
                  (gdt->expansion_direction << 2) |
                  (gdt->readable_and_writable << 1) | (gdt->access_bit);
  sregs.cs.present = 1;            // 段存在
  sregs.cs.db = gdt->segment_type; // Default operation size / Big flag
  sregs.cs.s = gdt->descriptor_bit;
  sregs.cs.l = 0;                // 长模式
  sregs.cs.g = gdt->granularity; // 粒度标志
  sregs.cs.avl = gdt->reserved_for_os;
  sregs.cs.unusable = 0; // 段可用

  sregs.ds.base = 0;
  sregs.ds.selector = 0;
  sregs.ds.limit = 65535;
  sregs.ds.g = 0;
  sregs.ds.s = 1;
  sregs.ds.present = 1;
  sregs.ds.type = 3;

  sregs.es = sregs.ds;
  sregs.fs = sregs.ds;
  sregs.gs = sregs.ds;
  sregs.ss = sregs.ds;

  if (ioctl(vcpu_fd, KVM_SET_SREGS, &sregs) < 0) {
    perror("can not set sregs");
    return 1;
  }

  struct kvm_regs regs;
  memset(&regs, 0, sizeof(regs));
  regs.rflags = 2;

  regs.rip = 128;
  regs.rsp = 0x00000000000ff000;

  regs.rax = 0x0000000000000006;
  regs.rbp = 0x10;
  regs.rdi = 0x21;
  if (ioctl(vcpu_fd, KVM_SET_REGS, &(regs)) < 0) {
    perror("KVM SET REGS\n");
    return 1;
  }

  for (;;) {
    int ret = ioctl(vcpu_fd, KVM_RUN, 0);
    if (ret < 0) {
      fprintf(stderr, "KVM_RUN failed\n");
      return 1;
    }
    switch (run->exit_reason) {
    case KVM_EXIT_IO:
      printf("IO port: %d, data: 0x%x\n", run->io.port,
             *(int *)((char *)(run) + run->io.data_offset));
      break;
    case KVM_EXIT_HLT:
      printf("kvm halt\n");
      struct kvm_regs output_regs;
      if (ioctl(vcpu_fd, KVM_GET_REGS, &(output_regs)) < 0) {
        perror("KVM SET REGS\n");
        return 1;
      }
      printf("rax=%llu\n", output_regs.rax);
      goto exit;
    case KVM_EXIT_INTERNAL_ERROR:
      printf("KVM_EXIT_INTERNAL_ERROR: suberror=%u\n", run->internal.suberror);
      goto exit;
    default:
      printf("exit reason: %d\n", run->exit_reason);
      goto exit;
    }
  }

exit:
  return 0;
}
