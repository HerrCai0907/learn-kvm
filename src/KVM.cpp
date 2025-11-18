#include "WARP.hpp"
#include "src/WasmModule/WasmModule.hpp"
#include "src/core/common/Span.hpp"
#include <cassert>
#include <cerrno>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <linux/kvm.h>
#include <sstream>
#include <string>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <unistd.h>

namespace wasm_kvm {

namespace {

struct __attribute__((packed)) gdt_entry_t {
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
  uint8_t long_mode : 1;
  // 0: 16 bit
  // 1: 32 bit
  uint8_t segment_type : 1;
  // 0: None
  // 1: limit * 4K
  uint8_t granularity : 1;

  uint8_t base_high; // 基地址高8位
};

typedef uint64_t page_table_entry_t;
#define PT_WRITABLE_SHIFT 1
#define PT_USER_SHIFT 2
#define PT_PRESENT_MASK (1ULL << 0)
#define PT_WRITABLE_MASK (1ULL << PT_WRITABLE_SHIFT)
#define PT_USER_MASK (1ULL << PT_USER_SHIFT)
#define PT_DIRTY_SHIFT 6
#define PT_DIRTY_MASK (1ULL << PT_DIRTY_SHIFT)
#define PT_PAGE_SIZE_SHIFT 7
#define PT_PAGE_SIZE_MASK (1ULL << PT_PAGE_SIZE_SHIFT)

#define PT_ADDRESS_MASK 0x000ffffffffff000ULL
#define PT_GET_ADDRESS(pt) (pt & PT_ADDRESS_MASK)

} // namespace

constexpr size_t KB = 1024U;
constexpr size_t MB = 1024U * KB;
constexpr size_t GB = 1024U * MB;

constexpr size_t PAGE_SIZE = 4U * KB;

constexpr static size_t MEMORY_SIZE = 4U * GB;

// guest phy memory layout
// GDT_LOC + TRAMPOLINE_LOC (4k)
// PML4_LOC | ... page tables ... | ... free page tables ... | (1GB)
// JOB_START_LOC (rest)

constexpr static size_t GDT_LOC = 0U;
constexpr static size_t GDT_ITEM_COUNT = 2U;
constexpr static size_t GDT_ITEM_SIZE = 8U;
constexpr static size_t TRAMPOLINE_LOC = GDT_LOC + GDT_ITEM_COUNT * GDT_ITEM_SIZE; // gdt 2 entries, each 8 bytes + padding

constexpr static size_t PML4_LOC = PAGE_SIZE;

constexpr static size_t JOB_START_VA = 16 * GB;
constexpr static size_t JOB_START_PA = 2 * GB;

constexpr static size_t JOB_STACK_VA = 4 * GB;
constexpr static size_t JOB_STACK_SIZE = 1 * MB;
constexpr static size_t JOB_STACK_PA = 2 * GB;

enum class PageKind {
  Size1GB,
  Size2MB,
  Size4KB,
};

class KVMManager {
public:
  int kvmHandler_ = -1;
  int vmHandler_ = -1;
  int vcpuHandler_ = -1;
  void *mem_ = MAP_FAILED;
  int kvm_run_mmap_size_ = 0;
  kvm_run *run_ = nullptr;
  size_t freePageTableLoc_ = PML4_LOC + PAGE_SIZE;

  ~KVMManager();

  bool initialize();
  bool isInitialized() const { return kvmHandler_ >= 0 && vmHandler_ >= 0 && mem_ != MAP_FAILED && vcpuHandler_ >= 0 && run_ != nullptr; }
  bool isUninitialized() const { return kvmHandler_ < 0 && vmHandler_ < 0 && mem_ == MAP_FAILED && vcpuHandler_ < 0 && run_ == nullptr; }

  void initMemory();
  void initTrampoline();
  bool initCPU();

  void addPageTableEntry(uint64_t virtualAddress, uint64_t physicalAddress, PageKind kind);

  vb::Span<uint8_t> getCodeSpan() {
    // only 1 job supported yet
    return {static_cast<uint8_t *>(mem_) + JOB_START_PA, MEMORY_SIZE - JOB_START_PA};
  }

  vb::Span<gdt_entry_t> getGDT() { return vb::Span<gdt_entry_t>{static_cast<gdt_entry_t *>(mem_), 2}; }
};

bool KVMManager::initialize() {
  assert(isUninitialized());

  kvmHandler_ = ::open("/dev/kvm", O_RDWR);
  if (kvmHandler_ < 0) {
    return false;
  }

  vmHandler_ = ioctl(kvmHandler_, KVM_CREATE_VM, 0);
  if (vmHandler_ < 0) {
    return false;
  }

  mem_ = ::mmap(NULL, MEMORY_SIZE, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS | MAP_NORESERVE, -1, 0);
  if (mem_ == MAP_FAILED) {
    return false;
  }

  struct kvm_userspace_memory_region region;
  std::memset(&region, 0, sizeof(region));
  region.slot = 0;
  region.guest_phys_addr = 0;
  region.memory_size = MEMORY_SIZE;
  region.userspace_addr = reinterpret_cast<uintptr_t>(mem_);
  if (ioctl(vmHandler_, KVM_SET_USER_MEMORY_REGION, &region) < 0) {
    return false;
  }

  kvm_run_mmap_size_ = ::ioctl(kvmHandler_, KVM_GET_VCPU_MMAP_SIZE, 0);
  if (kvm_run_mmap_size_ < 0) {
    return false;
  }
  vcpuHandler_ = ::ioctl(vmHandler_, KVM_CREATE_VCPU, 0);
  if (vcpuHandler_ < 0) {
    return false;
  }
  run_ = static_cast<kvm_run *>(::mmap(NULL, static_cast<size_t>(kvm_run_mmap_size_), PROT_READ | PROT_WRITE, MAP_SHARED, vcpuHandler_, 0));
  if (run_ == nullptr) {
    return false;
  }

  return true;
}

void KVMManager::initMemory() {
  assert(isInitialized());
  vb::Span<gdt_entry_t> gdt = getGDT();
  memset(&gdt[0], 0, sizeof(gdt_entry_t)); // 根据要求，第一个 gdt 为空
  gdt[1].limit_low = 0xFFFFU;
  gdt[1].base_low = 0x0000U;
  gdt[1].base_mid = 0x00U;
  gdt[1].access_bit = 0U;
  gdt[1].readable_and_writable = 1U;
  gdt[1].expansion_direction = 0U;
  gdt[1].executable_segment = 1U;
  gdt[1].descriptor_bit = 1U;
  gdt[1].descriptor_privilege_level = 0U;
  gdt[1].segment_is_in_memory = 1U;
  gdt[1].limit_high = 0xFU;
  gdt[1].reserved_for_os = 0U;
  gdt[1].long_mode = 1U;
  gdt[1].segment_type = 0U;
  gdt[1].granularity = 1U;
  gdt[1].base_high = 0x00U;

  page_table_entry_t *plm4_entry = reinterpret_cast<page_table_entry_t *>(static_cast<char *>(mem_) + PML4_LOC);
  memset(plm4_entry, 0, PAGE_SIZE);

  addPageTableEntry(0ULL, 0ULL, PageKind::Size1GB);
}

void KVMManager::addPageTableEntry(uint64_t virtualAddress, uint64_t physicalAddress, PageKind kind) {
  size_t const pml4Index = (virtualAddress >> 39U) & 0x1FFU; // 47-39位
  size_t const pdptIndex = (virtualAddress >> 30U) & 0x1FFU; // 38-30位
  size_t const pdtIndex = (virtualAddress >> 21U) & 0x1FFU;  // 29-21位
  size_t const ptIndex = (virtualAddress >> 12U) & 0x1FFU;   // 20-12位

  // PML4
  page_table_entry_t *pml4Entry = reinterpret_cast<page_table_entry_t *>(static_cast<char *>(mem_) + PML4_LOC);
  size_t pdptLoc = 0U;
  if (PT_PRESENT_MASK != (pml4Entry[pml4Index] & PT_PRESENT_MASK)) {
    pdptLoc = freePageTableLoc_;
    freePageTableLoc_ += PAGE_SIZE;
    memset(static_cast<uint8_t *>(mem_) + pdptLoc, 0, PAGE_SIZE);
    pml4Entry[pml4Index] = PT_PRESENT_MASK | PT_WRITABLE_MASK | pdptLoc;
    std::cout << "add PML4 item: va 0x" << std::hex << virtualAddress << std::dec << std::endl;
  } else {
    pdptLoc = PT_GET_ADDRESS(pml4Entry[pml4Index]);
    std::cout << "has PML4 item: va 0x" << std::hex << virtualAddress << std::dec << " pdptLoc " << pdptLoc << std::endl;
  }

  // PDPT
  page_table_entry_t *pdptEntry = reinterpret_cast<page_table_entry_t *>(static_cast<char *>(mem_) + pdptLoc);
  if (kind == PageKind::Size1GB) {
    if (PT_PRESENT_MASK != (pdptEntry[pdptIndex] & PT_PRESENT_MASK)) {
      std::cout << "  add PDPT item[" << pdptIndex << "]: va 0x" << std::hex << virtualAddress << " as 1GB page point to 0x" << physicalAddress
                << std::dec << "\n";
      pdptEntry[pdptIndex] = PT_PRESENT_MASK | PT_WRITABLE_MASK | PT_PAGE_SIZE_MASK | physicalAddress;
    } else {
      std::cout << "  has PDPT item: va 0x" << std::hex << virtualAddress << " pa 0x" << PT_GET_ADDRESS(pdptEntry[pdptIndex]) << std::dec
                << std::endl;
      assert((pdptEntry[pdptIndex] & PT_PAGE_SIZE_MASK) == PT_PAGE_SIZE_MASK);
      assert(physicalAddress == PT_GET_ADDRESS(pdptEntry[pdptIndex]));
    }
    return;
  }
  size_t pdtLoc = 0U;
  if (PT_PRESENT_MASK != (pdptEntry[pdptIndex] & PT_PRESENT_MASK)) {
    pdtLoc = freePageTableLoc_;
    freePageTableLoc_ += PAGE_SIZE;
    memset(static_cast<uint8_t *>(mem_) + pdtLoc, 0, PAGE_SIZE);
    pdptEntry[pdptIndex] = PT_PRESENT_MASK | PT_WRITABLE_MASK | pdtLoc;
    std::cout << "  add PDPT item[" << pdptIndex << "]: va 0x" << std::hex << virtualAddress << std::dec << std::endl;
  } else {
    pdtLoc = PT_GET_ADDRESS(pdptEntry[pdptIndex]);
    std::cout << "  has PDPT item: va 0x" << std::hex << virtualAddress << std::dec << " pdptLoc " << pdtLoc << std::endl;
  }

  // PDT
  page_table_entry_t *pdtEntry = reinterpret_cast<page_table_entry_t *>(static_cast<char *>(mem_) + pdtLoc);
  if (kind == PageKind::Size2MB) {
    if (PT_PRESENT_MASK != (pdtEntry[pdtIndex] & PT_PRESENT_MASK)) {
      std::cout << "    add PPT item[" << pdtIndex << "]: va 0x" << std::hex << virtualAddress << " as 1GB page point to 0x" << physicalAddress
                << std::dec << "\n";
      pdtEntry[pdtIndex] = PT_PRESENT_MASK | PT_WRITABLE_MASK | PT_PAGE_SIZE_MASK | physicalAddress;
    } else {
      std::cout << "    has PPT item: va 0x" << std::hex << virtualAddress << " pa 0x" << PT_GET_ADDRESS(pdtEntry[pdtIndex]) << std::dec << std::endl;
      assert((pdtEntry[pdtIndex] & PT_PAGE_SIZE_MASK) == PT_PAGE_SIZE_MASK);
      assert(physicalAddress == PT_GET_ADDRESS(pdtEntry[pdtIndex]));
    }
    return;
  }
  size_t ptLoc = 0U;
  if (PT_PRESENT_MASK != (pdtEntry[pdtIndex] & PT_PRESENT_MASK)) {
    ptLoc = freePageTableLoc_;
    freePageTableLoc_ += PAGE_SIZE;
    memset(static_cast<uint8_t *>(mem_) + ptLoc, 0, PAGE_SIZE);
    pdtEntry[pdtIndex] = PT_PRESENT_MASK | PT_WRITABLE_MASK | ptLoc;
    std::cout << "    add PDT item[" << pdtIndex << "]: va 0x" << std::hex << virtualAddress << std::dec << std::endl;
  } else {
    ptLoc = PT_GET_ADDRESS(pdtEntry[pdtIndex]);
  }

  // PT
  page_table_entry_t *ptEntry = reinterpret_cast<page_table_entry_t *>(static_cast<char *>(mem_) + ptLoc);
  if (PT_PRESENT_MASK != (ptEntry[ptIndex] & PT_PRESENT_MASK)) {
    freePageTableLoc_ += PAGE_SIZE;
    memset(static_cast<uint8_t *>(mem_) + ptLoc, 0, PAGE_SIZE);
    ptEntry[ptIndex] = PT_PRESENT_MASK | PT_PAGE_SIZE_MASK | PT_WRITABLE_MASK | physicalAddress;
    std::cout << "      add PT item[" << ptIndex << "]: va 0x" << std::hex << virtualAddress << "as 4kB page point to 0x" << physicalAddress
              << std::dec << "\n";
  } else {
    assert(physicalAddress == PT_GET_ADDRESS(ptEntry[ptIndex]));
  }
}

void KVMManager::initTrampoline() {
  assert(isInitialized());
  char *trampoline = static_cast<char *>(mem_) + TRAMPOLINE_LOC;
  size_t i = 0;
  // out 10, ax
  trampoline[i++] = 0x66;
  trampoline[i++] = 0xE7;
  trampoline[i++] = 0x0A;
  // call rax
  trampoline[i++] = 0xFF;
  trampoline[i++] = 0xD0;
  // hlt
  trampoline[i++] = 0xF4;
}

bool KVMManager::initCPU() {
  assert(isInitialized());
  struct kvm_sregs sregs;
  if (ioctl(vcpuHandler_, KVM_GET_SREGS, &sregs) < 0) {
    return false;
  }

  sregs.gdt.base = GDT_LOC;
  sregs.gdt.limit = GDT_ITEM_COUNT * GDT_ITEM_SIZE - 1;

  sregs.cr0 |= (1ULL << 0ULL);  // enable PE
  sregs.cr0 |= (1ULL << 31ULL); // enable PG

  sregs.cr3 = PML4_LOC; // page table base addr

  sregs.cr4 |= (1 << 5); // enable PAE

  sregs.efer |= (1 << 8);  // enable LME
  sregs.efer |= (1 << 10); // enable LMA

  constexpr int gdt_index = 1;
  gdt_entry_t gdt = getGDT()[gdt_index];
  sregs.cs.base = static_cast<uint32_t>(gdt.base_low) | (static_cast<uint32_t>(gdt.base_mid) << 16) | (static_cast<uint32_t>(gdt.base_high) << 24);
  sregs.cs.limit =
      (static_cast<uint32_t>(gdt.limit_low) | (static_cast<uint32_t>(gdt.limit_high) << 16) + 1U) * (gdt.granularity == 1U ? 4096U : 1U) - 1U;
  sregs.cs.selector = static_cast<uint16_t>(8 * gdt_index);
  sregs.cs.type =
      static_cast<uint8_t>((static_cast<uint32_t>(gdt.executable_segment) << 3U) | (static_cast<uint32_t>(gdt.expansion_direction) << 2U) |
                           (static_cast<uint32_t>(gdt.readable_and_writable) << 1U) | (static_cast<uint32_t>(gdt.access_bit)));
  sregs.cs.present = 1;           // 段存在
  sregs.cs.db = gdt.segment_type; // Default operation size / Big flag
  sregs.cs.s = gdt.descriptor_bit;
  sregs.cs.l = gdt.long_mode;   // 长模式
  sregs.cs.g = gdt.granularity; // 粒度标志
  sregs.cs.avl = gdt.reserved_for_os;
  sregs.cs.unusable = 0; // 段可用

  sregs.ds.base = 0;
  sregs.ds.selector = 0;
  sregs.ds.limit = 0xFFFFFFFFU;
  sregs.ds.g = gdt.granularity;
  sregs.ds.s = gdt.descriptor_bit;
  sregs.ds.present = 1;
  sregs.ds.type = 3;

  sregs.es = sregs.ds;
  sregs.fs = sregs.ds;
  sregs.gs = sregs.ds;
  sregs.ss = sregs.ds;

  if (ioctl(vcpuHandler_, KVM_SET_SREGS, &sregs) < 0) {
    return false;
  }
  return true;
}

KVMManager::~KVMManager() {
  if (kvmHandler_ >= 0) {
    ::close(kvmHandler_);
    kvmHandler_ = -1;
  }
  if (vmHandler_ >= 0) {
    ::close(vmHandler_);
    vmHandler_ = -1;
  }
  if (mem_ != MAP_FAILED) {
    ::munmap(mem_, MEMORY_SIZE);
    mem_ = nullptr;
  }
  if (vcpuHandler_ >= 0) {
    ::close(vcpuHandler_);
    vcpuHandler_ = -1;
  }
  if (run_ != nullptr) {
    ::munmap(run_, static_cast<size_t>(kvm_run_mmap_size_));
    run_ = nullptr;
  }
}

} // namespace wasm_kvm

std::string readBinaryFile(std::string const &path) {
  std::ifstream const ifs{path, std::ios::in | std::ios::binary};
  if (!ifs.is_open())
    throw std::runtime_error{"cannot open file: " + path};
  std::stringstream buffer;
  buffer << ifs.rdbuf();
  return std::move(buffer).str();
}

int main() {
  vb::WasmModule::initEnvironment(malloc, realloc, free);
  using namespace wasm_kvm;

  KVMManager kvmManager{};
  kvmManager.initialize();
  kvmManager.initMemory();
  kvmManager.initCPU();
  kvmManager.initTrampoline();

  struct kvm_regs regs;
  memset(&regs, 0, sizeof(regs));
  regs.rflags = 2;

  regs.rip = TRAMPOLINE_LOC; // system use first 8 pages
  regs.rsp = JOB_STACK_VA + JOB_STACK_SIZE;
  kvmManager.addPageTableEntry(JOB_STACK_VA, JOB_STACK_PA, PageKind::Size1GB);

  WARP warp{};
  vb::WasmModule::CompileResult compileResult = warp.compile(readBinaryFile("/home/q540239/learn-kvm/add.wasm"));
  uint32_t const totalSize = warp.initializeModule(compileResult.getModule().span(), kvmManager.getCodeSpan(), nullptr);
  kvmManager.addPageTableEntry(JOB_START_VA, JOB_START_PA, (totalSize >= 4 * KB) ? PageKind::Size2MB : PageKind::Size4KB); // FIXME

  regs.rax = JOB_START_VA + 492; // trampoline will call rax
  regs.rbx = JOB_START_VA + warp.getLinearMemoryBaseOffset();
  regs.rbp = 10; // wasm-compiler wasm abi arg 0
  regs.rdi = 21; // wasm-compiler wasm abi arg 1

  if (ioctl(kvmManager.vcpuHandler_, KVM_SET_REGS, &(regs)) < 0) {
    perror("KVM SET REGS\n");
    return 1;
  }

  for (;;) {
    int ret = ioctl(kvmManager.vcpuHandler_, KVM_RUN, 0);
    if (ret < 0) {
      fprintf(stderr, "KVM_RUN failed\n");
      return 1;
    }
    switch (kvmManager.run_->exit_reason) {
    case KVM_EXIT_IO: {
      int io_data = 0;
      std::memcpy(&io_data, static_cast<char *>(static_cast<void *>(kvmManager.run_)) + kvmManager.run_->io.data_offset, sizeof(io_data));
      printf("IO port: %d, data: 0x%x\n", kvmManager.run_->io.port, io_data);
      break;
    }
    case KVM_EXIT_MMIO: {
      printf("KVM_EXIT_MMIO: phys_addr=0x%llx, len=%u, is_write=%u\n", kvmManager.run_->mmio.phys_addr, kvmManager.run_->mmio.len,
             kvmManager.run_->mmio.is_write);
      break;
    }
    case KVM_EXIT_HLT:
      struct kvm_regs output_regs;
      if (ioctl(kvmManager.vcpuHandler_, KVM_GET_REGS, &(output_regs)) < 0) {
        perror("KVM GET REGS\n");
        return 1;
      }
      printf("rax = %llu\n", output_regs.rax);
      printf("kvm halt\n");
      goto exit;
    case KVM_EXIT_SHUTDOWN:
      printf("kvm shutdown\n");
      goto exit;
    case KVM_EXIT_INTERNAL_ERROR:
      printf("KVM_EXIT_INTERNAL_ERROR: suberror=%u\n", kvmManager.run_->internal.suberror);
      goto exit;
    case KVM_EXIT_FAIL_ENTRY:
      printf("KVM_EXIT_FAIL_ENTRY: suberror=%llx\n", kvmManager.run_->fail_entry.hardware_entry_failure_reason);
      goto exit;
    default:
      printf("exit reason: %d\n", kvmManager.run_->exit_reason);
      goto exit;
    }
  }

exit:
  return 0;
}
