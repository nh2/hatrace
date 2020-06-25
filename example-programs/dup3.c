#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char const *argv[])
{
  int fd;

  fd = dup3(0, 1, O_CLOEXEC);
  if (fd < 0) {
    perror("dup3 O_CLOEXEC failed");
    return fd;
  }
  fd = dup3(0, 1, 0);
  if (fd < 0) {
    perror("dup3 failed");
    return fd;
  }
}
