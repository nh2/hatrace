#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: set-tid-address\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }
  int tid;
  int res = syscall(SYS_set_tid_address, &tid);
  fprintf(stderr, "TID: %d\n", res);
  return 0;
}
