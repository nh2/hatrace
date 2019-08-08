#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <malloc.h>
#include <unistd.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: mprotect\n");
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

  buffer = memalign(pagesize, 4 * pagesize);
  if (buffer == NULL) {
    perror("memalign");
    exit(1);
  }

  int res = mprotect(buffer + pagesize * 2, pagesize, PROT_READ);
  if (res == -1) {
    perror("mprotect");
    exit(1);
  }

  return 0;
}
