#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/syscall.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: bad-open-pointer\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }
  void* ptr = (void*)1;
  int fd = syscall(SYS_open, ptr);
  if (fd == -1) {
    printf("opening a file with a NULL pathname failed as expected");
    return 0;
  }

  perror("Unexpectedly bad pointer pathname was opened");
  if(close(fd) != 0) {
    perror("close");
    exit(2);
  }
  exit(1);
}
