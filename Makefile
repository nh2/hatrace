.PHONY: example-programs
example-programs: example-programs/hello

example-programs/hello: example-programs/hello.asm
	nasm -f elf64 example-programs/hello.asm
	ld -e _start -o example-programs/hello example-programs/hello.o
	rm example-programs/hello.o
