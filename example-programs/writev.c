#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/uio.h>
#include <unistd.h>

int main(int argc, char *const argv[])
{
  // example taken from man for writev(2):
  char *str0 = "hello ";
  char *str1 = "world\n";
  struct iovec iov[2];
  ssize_t nwritten;

  iov[0].iov_base = str0;
  iov[0].iov_len = strlen(str0);
  iov[1].iov_base = str1;
  iov[1].iov_len = strlen(str1);

  nwritten = writev(STDOUT_FILENO, iov, 2);
  printf("%ld\n", nwritten);
  printf("%p\n", iov[0].iov_base);
  printf("%p\n", iov[1].iov_base);

  if (nwritten == -1) {
    perror("writev");
    exit(1);
  }
  exit(0);
}
