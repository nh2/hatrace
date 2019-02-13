EXAMPLE_PROGRAMS :=
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-i386
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-i386-elf64
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-x86_64
EXAMPLE_PROGRAMS += example-programs-build/segfault
EXAMPLE_PROGRAMS += example-programs-build/atomic-write

.PHONY: example-programs
example-programs: $(EXAMPLE_PROGRAMS)

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

example-programs-build/atomic-write: example-programs/atomic-write.c
	mkdir -p example-programs-build
	gcc -std=c99 -Wall -Werror example-programs/atomic-write.c -o example-programs-build/atomic-write
