;This program segfaults by reading from memory address 0.

section     .text
global      _start                              ;must be declared for linker (ld)

_start:                                         ;tell linker entry point

    mov     rax,0x0                             ;reading something from NULL should segfault
