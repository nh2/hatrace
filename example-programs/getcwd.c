#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char const *argv[])
{
  char buf[4096];

  char * retval = getcwd(buf, sizeof(buf));
  if (retval == NULL) {
    perror("getcwd");
    return EXIT_FAILURE;
  }

  puts(buf);

  return EXIT_SUCCESS;
}
