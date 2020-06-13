#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    puts("unlink /path/to/file/to/delete\n");
    return 1;
  }

  const char* filepath = argv[1];
  if (access(filepath, 0) != 0) {
    fprintf(stderr, "couldn't access filepath %s\n", filepath);
    return 2;
  }

  int retval = unlink(filepath);
  if (retval != 0) {
    fprintf(stderr, "couldn't unlink file %s\n", filepath);
  }

  return retval;
}
