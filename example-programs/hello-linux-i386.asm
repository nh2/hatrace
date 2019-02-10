;From http://asm.sourceforge.net/intro/hello.html

;Does only 2 syscalls:
;write("Hello, world!")
;exit(0)

;compile into a static executable with e.g.:
;    nasm -f elf64 hello-linux-i386.asm -o hello.o && ld -e _start -o hello hello.o

;Note this file uses the 32-bit legacy syscall API with `int 0x80`!
;This means it will use the 32-bit syscall numbers, not the x86_64 ones,
;even when compiled as elf64.

section     .text
global      _start                              ;must be declared for linker (ld)

_start:                                         ;tell linker entry point

    mov     edx,len                             ;message length
    mov     ecx,msg                             ;message to write
    mov     ebx,1                               ;file descriptor (stdout)
    mov     eax,4                               ;system call number (sys_write)
    int     0x80                                ;call kernel

    mov     ebx,0                               ;exit code
    mov     eax,1                               ;system call number (sys_exit)
    int     0x80                                ;call kernel

section     .data

msg     db  'Hello, world!',0xa                 ;our dear string
len     equ $ - msg                             ;length of our dear string
