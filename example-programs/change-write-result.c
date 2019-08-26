#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char const *argv[])
{
  int res = write(1, "hello", 5);

  // from man for exit(3):
  // The exit() function causes normal process termination and the value
  // of status & 0377 is returned to the parent
  // so only the last 8 bits are actually used
  if (res == -1) {
    exit(errno); // the error is set as an exit code to validate expectations in test case
  } else {
    exit(res);
  }
}
