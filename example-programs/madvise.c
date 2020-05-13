#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: madvise\n");
  exit(1);
}

static char *buffer;

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }

  long pagesize = sysconf(_SC_PAGESIZE);
  if (pagesize == -1) {
    perror("sysconf");
    exit(1);
  }

  buffer = memalign(pagesize, pagesize);
  if (buffer == NULL) {
    perror("memalign");
    exit(1);
  }

  int res = madvise(buffer, pagesize, MADV_RANDOM);
  if (res == -1) {
    perror("madvise");
    exit(1);
  }

  return 0;
}
