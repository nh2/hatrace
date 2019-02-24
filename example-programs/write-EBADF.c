#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *const argv[])
{
  // Write to FD -1 to trigger EBADF
  ssize_t res = write(-1, "hello", 5);

  if (res == -1) {
    perror("write");
    exit(1);
  } else {
    exit(0);
  }
}
