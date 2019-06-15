EXAMPLE_PROGRAMS :=
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-i386
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-i386-elf64
EXAMPLE_PROGRAMS += example-programs-build/hello-linux-x86_64
EXAMPLE_PROGRAMS += example-programs-build/segfault
EXAMPLE_PROGRAMS += example-programs-build/execve
EXAMPLE_PROGRAMS += example-programs-build/execve-linux-null-envp
EXAMPLE_PROGRAMS += example-programs-build/atomic-write
EXAMPLE_PROGRAMS += example-programs-build/write-EBADF
EXAMPLE_PROGRAMS += example-programs-build/access-itself

.PHONY: example-programs
example-programs: $(EXAMPLE_PROGRAMS)

# Most examxple C programs are linked statically here so that they do no
# syscalls related to dynamic loading, thus avoiding a syscall flood
# unrelated to the key thing each program does.

example-programs-build/%-i386: example-programs/%-i386.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf $< -o $@.o
	ld -m elf_i386 -e _start $@.o -o $@
	rm $@.o

example-programs-build/%-i386-elf64: example-programs/%-i386.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf64 $< -o $@.o
	ld -e _start $@.o -o $@
	rm $@.o

example-programs-build/%-x86_64: example-programs/%-x86_64.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf64 $< -o $@.o
	ld -e _start $@.o -o $@
	rm $@.o

example-programs-build/%: example-programs/%.asm
	mkdir -p example-programs-build
	nasm -Wall -Werror -f elf64 $< -o $@.o
	ld -e _start $@.o -o $@
	rm $@.o

example-programs-build/%: example-programs/%.c
	mkdir -p example-programs-build
	gcc -static -std=c99 -Wall -Werror $< -o $@
