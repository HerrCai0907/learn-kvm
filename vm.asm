%define PAGE_SIZE 4096

gdt_table:
  times 1 * PAGE_SIZE - ($ - $$) db 0
PML4_table:
  times 2 * PAGE_SIZE - ($ - $$) db 0
PDPT_table:
  times 3 * PAGE_SIZE - ($ - $$) db 0
PD_table:
  times 4 * PAGE_SIZE - ($ - $$) db 0
PT_table:
  times 5 * PAGE_SIZE - ($ - $$) db 0

times 8 * PAGE_SIZE - ($ - $$) db 0

; code
; bits 32
; _start:
;   jmp 0x08:long_mode_start

bits 64
long_mode_start:
  mov r11, 0xFFFFFFFF
  mov r12, 1
  add r11, r12
  hlt
