
.intel_syntax noprefix
.global _start
_start:
  out   0x10, ax
  // call  rax


_foo:
  // lea   rsp, [rsp - 0x98]
  // mov   eax, ebp
  // add   eax, edi
  // lea   rsp, [rsp + 0x98]
  // ret
