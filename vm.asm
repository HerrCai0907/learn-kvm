; remain for GDT
times 128 - ($ - $$) db 0

; code
bits 32
  mov eax, 4294967295
  hlt
