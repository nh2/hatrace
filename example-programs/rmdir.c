#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void die_usage(void) {
  fputs("Usage: rmdir /path/to/directory/to/delete\n\n", stderr);
  exit(1);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    die_usage();
  }

  const char* directory = argv[1];
  int retval = rmdir(directory);
  if (retval != 0) {
    printf("couldn't rmdir directory %s", directory);
  }

  return retval;
}
