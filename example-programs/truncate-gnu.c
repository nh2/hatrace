#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void die_usage(void) {
  fputs("Usage: truncate /path/to/file size\n\n", stderr);
  exit(1);
}

int main(int argc, char* argv[]) {
  if (argc != 3) {
    die_usage();
  }

  const char* filename = argv[1];
  int size = atoi(argv[2]);
  int retval = truncate(filename, size);
  if (retval != 0) {
    perror("could not truncate file\n");
  }

  return retval;
}
