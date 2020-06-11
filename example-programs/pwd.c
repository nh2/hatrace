#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char const *argv[])
{
  char buf[4096];

  getcwd(buf, sizeof(buf));
  if (errno) {
    perror("getcwd");
    return EXIT_FAILURE;
  }

  puts(buf);
  
  return EXIT_SUCCESS;
}
