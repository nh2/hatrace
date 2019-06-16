#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/types.h>
#include <signal.h>
#include <stdio.h>
#include <assert.h>

int main(int argc, char *argv[])
{
    int *init_program_break = (int *) syscall(SYS_brk, 0x0);
    int *greater_program_break = (int *) syscall(SYS_brk, init_program_break + 0x100);
    int *restored_program_break = (int *) syscall(SYS_brk, greater_program_break - 0x100);
    assert(init_program_break == restored_program_break);
    return 0;
}

