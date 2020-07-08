#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: bad-read-pointer\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }

  int fd = open("stack.yaml", O_RDONLY);
  if (fd == -1) {
    perror("can't open stack.yaml");
    exit(1);
  }

  void* ptr = (void*)42;
  int res = read(fd, ptr, 1);
  if (res == -1) {
    if (errno == EFAULT) {
      printf("can't read stack.yaml into a bad pointer as expected");
      return 0;
    } else {
      perror("read");
      exit(2);
    }
  }

  printf("Unexpectedly read into a bad pointer");
  if(close(fd) != 0) {
    perror("close");
    exit(3);
  }
  exit(4);
}
