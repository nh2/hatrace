#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: dup3\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }

  int fd = dup3(0, 1, O_CLOEXEC);
  if (fd == -1) {
    perror("dup3 O_CLOEXEC failed");
    exit(1);
  }
  fd = dup3(0, 1, 0);
  if (fd == -1) {
    perror("dup3 failed");
    exit(1);
  }
}
