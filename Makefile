EXAMPLE_PROGRAMS :=
EXAMPLE_PROGRAMS += example-programs/hello-linux-i386-elf64
EXAMPLE_PROGRAMS += example-programs/hello-linux-x86_64
EXAMPLE_PROGRAMS += example-programs/segfault

.PHONY: example-programs
example-programs: $(EXAMPLE_PROGRAMS)

example-programs/hello-linux-i386-elf64: example-programs/hello-linux-i386.asm
	nasm -Wall -Werror -f elf64 example-programs/hello-linux-i386.asm -o example-programs/hello-linux-i386-elf64.o
	ld -e _start -o example-programs/hello-linux-i386-elf64 example-programs/hello-linux-i386-elf64.o
	rm example-programs/hello-linux-i386-elf64.o

example-programs/hello-linux-x86_64: example-programs/hello-linux-x86_64.asm
	nasm -Wall -Werror -f elf64 example-programs/hello-linux-x86_64.asm -o example-programs/hello-linux-x86_64.o
	ld -e _start -o example-programs/hello-linux-x86_64 example-programs/hello-linux-x86_64.o
	rm example-programs/hello-linux-x86_64.o

example-programs/segfault: example-programs/segfault.asm
	nasm -Wall -Werror -f elf64 example-programs/segfault.asm -o example-programs/segfault.o
	ld -e _start -o example-programs/segfault example-programs/segfault.o
	rm example-programs/segfault.o
