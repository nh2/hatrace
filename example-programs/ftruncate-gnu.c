#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>

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
  int fd = open(filename, O_RDWR);
  if (fd < 0) {
    fprintf(stderr, "could not open file %s\n", filename);
  }
  int retval = ftruncate(fd, size);
  if (retval != 0) {
    fprintf(stderr, "could not truncate file %s to %d\n", filename, size);
  }
  close(fd);

  return retval;
}
