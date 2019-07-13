#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <asm/prctl.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: get-fs\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }
  unsigned long fs;
  int res = syscall(SYS_arch_prctl, ARCH_GET_FS, &fs);
  if (res == -1) {
    perror("access");
    exit(1);
  }

  printf("FS: %lx\n", fs);
  return 0;
}
