#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void die_usage(void)
{
  fputs("Usage: chdir /path/to/directory/to/chdir\n", stderr);
  exit(1);
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    die_usage();
  }

  const char* directory = argv[1];

  int retval = chdir(directory);
  if (retval != 0) {
    fprintf(stderr, "couldn't chdir to directory %s\n", directory);
  }

  return retval;
}
