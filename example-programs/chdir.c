#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    puts("chdir /path/to/directory/to/chdir\n");
    return 1;
  }

  const char* directory = argv[1];

  int retval = chdir(directory);
  if (retval != 0) {
    printf("couldn't chdir to directory %s", directory);
  }

  return retval;
}
