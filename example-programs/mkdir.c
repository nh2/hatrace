#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>

void die_usage(void) {
  fputs("Usage: mkdir /path/to/directory/to/create\n", stderr);
  exit(1);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    die_usage();
  }

  const char* directory = argv[1];
  int retval = mkdir(directory, S_IRWXU);
  if (retval != 0) {
    fprintf(stderr, "couldn't mkdir directory %s\n", directory);
  }

  return retval;
}
