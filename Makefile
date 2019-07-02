EXAMPLE_SRC := example-programs
EXAMPLE_DST := example-programs-build

EXAMPLE_PROGRAMS :=
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/hello-linux-i386
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/hello-linux-i386-elf64
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/hello-linux-x86_64
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/symlinkat
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/poll
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/segfault
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/execve
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/execve-linux-null-envp
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/atomic-write
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/write-EBADF
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/access-itself
EXAMPLE_PROGRAMS += $(EXAMPLE_DST)/trigger-time

.PHONY: example-programs
example-programs: $(EXAMPLE_PROGRAMS)

# Most examxple C programs are linked statically here so that they do no
# syscalls related to dynamic loading, thus avoiding a syscall flood
# unrelated to the key thing each program does.

$(EXAMPLE_DST)/%-i386: $(EXAMPLE_SRC)/%-i386.asm
	mkdir -p $(EXAMPLE_DST)
	nasm -Wall -Werror -f elf $< -o $@.o
	ld -m elf_i386 -e _start $@.o -o $@
	rm $@.o

$(EXAMPLE_DST)/%-i386-elf64: $(EXAMPLE_SRC)/%-i386.asm
	mkdir -p $(EXAMPLE_DST)
	nasm -Wall -Werror -f elf64 $< -o $@.o
	ld -e _start $@.o -o $@
	rm $@.o

$(EXAMPLE_DST)/%-x86_64: $(EXAMPLE_SRC)/%-x86_64.asm
	mkdir -p $(EXAMPLE_DST)
	nasm -Wall -Werror -f elf64 $< -o $@.o
	ld -e _start $@.o -o $@
	rm $@.o

$(EXAMPLE_DST)/%: $(EXAMPLE_SRC)/%.asm
	mkdir -p $(EXAMPLE_DST)
	nasm -Wall -Werror -f elf64 $< -o $@.o
	ld -e _start $@.o -o $@
	rm $@.o

$(EXAMPLE_DST)/%: $(EXAMPLE_SRC)/%.c
	mkdir -p $(EXAMPLE_DST)
	gcc -static -std=c99 -Wall -Werror $< -o $@
