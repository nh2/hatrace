;Adapted from http://asm.sourceforge.net/intro/hello.html

;Does only 2 syscalls:
;write("Hello, world!")
;exit(0)

;compile into a static executable with e.g.:
;    nasm -f elf64 hello-linux-x86_64.asm -o hello.o && ld -e _start -o hello hello.o

;Note this file uses the non legacy syscall API with `syscall` instruction.
;This means it will use the x86_64 syscall numbers, not the legacy i386 ones.

section     .text
global      _start                              ;must be declared for linker (ld)

_start:                                         ;tell linker entry point

    mov     rdx,len                             ;message length
    mov     rsi,msg                             ;message to write
    mov     rdi,1                               ;file descriptor (stdout)
    mov     rax,1                               ;system call number (sys_write)
    syscall                                     ;call kernel

    mov     rdi,0                               ;exit code
    mov     rax,60                              ;system call number (sys_exit)
    syscall                                     ;call kernel

section     .data

msg     db  'Hello, world!',0xa                 ;our dear string
len     equ $ - msg                             ;length of our dear string
