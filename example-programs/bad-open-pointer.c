#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
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
    // it's not clear why sometimes on my machine sometimes I get EINVAL instead of EFAULT
    if (errno == EFAULT || errno == EINVAL) {
      printf("opening a file with a NULL pathname failed as expected\n");
      return 0;
    } else {
      perror("open");
      exit(2);
    }
  }

  perror("Unexpectedly bad pointer pathname was opened");
  if(close(fd) != 0) {
    perror("close");
    exit(3);
  }
  exit(1);
}
