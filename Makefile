EXAMPLE_PROGRAMS :=
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-i386
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-i386-elf64
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-x86_64
EXAMPLE_PROGRAMS += example-programs-build/segfault
EXAMPLE_PROGRAMS += example-programs-build/execve
EXAMPLE_PROGRAMS += example-programs-build/execve-linux-null-envp
EXAMPLE_PROGRAMS += example-programs-build/atomic-write
EXAMPLE_PROGRAMS += example-programs-build/write-EBADF

.PHONY: example-programs
example-programs: $(EXAMPLE_PROGRAMS)

# Most examxple C programs are linked statically here so that they do no
# syscalls related to dynamic loading, thus avoiding a syscall flood
# unrelated to the key thing each program does.

example-programs-build/hello-linux-i386: example-programs/hello-linux-i386.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf example-programs/hello-linux-i386.asm -o example-programs-build/hello-linux-i386.o
	ld -m elf_i386 -e _start example-programs-build/hello-linux-i386.o -o example-programs-build/hello-linux-i386
	rm example-programs-build/hello-linux-i386.o

example-programs-build/hello-linux-i386-elf64: example-programs/hello-linux-i386.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf64 example-programs/hello-linux-i386.asm -o example-programs-build/hello-linux-i386-elf64.o
	ld -e _start example-programs-build/hello-linux-i386-elf64.o -o example-programs-build/hello-linux-i386-elf64
	rm example-programs-build/hello-linux-i386-elf64.o

example-programs-build/hello-linux-x86_64: example-programs/hello-linux-x86_64.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf64 example-programs/hello-linux-x86_64.asm -o example-programs-build/hello-linux-x86_64.o
	ld -e _start example-programs-build/hello-linux-x86_64.o -o example-programs-build/hello-linux-x86_64
	rm example-programs-build/hello-linux-x86_64.o

example-programs-build/segfault: example-programs/segfault.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf64 example-programs/segfault.asm -o example-programs-build/segfault.o
	ld -e _start example-programs-build/segfault.o -o example-programs-build/segfault
	rm example-programs-build/segfault.o

example-programs-build/execve: example-programs/execve.c
	mkdir -p example-programs-build
	gcc -static -std=c99 -Wall -Werror -g example-programs/execve.c -o example-programs-build/execve

example-programs-build/execve-linux-null-envp: example-programs/execve-linux-null-envp.c
	mkdir -p example-programs-build
	gcc -static -std=c99 -Wall -Werror -g example-programs/execve-linux-null-envp.c -o example-programs-build/execve-linux-null-envp

example-programs-build/atomic-write: example-programs/atomic-write.c
	mkdir -p example-programs-build
	gcc -static -std=c99 -Wall -Werror -g example-programs/atomic-write.c -o example-programs-build/atomic-write

example-programs-build/write-EBADF: example-programs/write-EBADF.c
	mkdir -p example-programs-build
	gcc -static -std=c99 -Wall -Werror -g example-programs/write-EBADF.c -o example-programs-build/write-EBADF
