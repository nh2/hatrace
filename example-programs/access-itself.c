#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: access-itself\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }
  int res = access(argv[0], X_OK);
  if (res == -1) {
    perror("access");
    exit(1);
  }
}
