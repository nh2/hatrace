#include <sched.h>
#include <stdio.h>
#include <stdlib.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: sched_yield\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }

  int res = sched_yield();
  if (res == -1) {
    perror("sched_yield");
    exit(1);
  }

  return 0;
}
