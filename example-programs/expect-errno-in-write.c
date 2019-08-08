#include <unistd.h>
#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char const *argv[])
{
  int res = write(1, "hello", 5);

  if (res == -1) {
    exit(errno); // the error is set as an exit code to validate expectations in test case
  } else {
    printf("write syscall was successful even though in test case it should fail");
    exit(1);
  }
}
