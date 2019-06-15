#define _GNU_SOURCE
#include <unistd.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <string.h>
#include <time.h>

int main(int argc, char const *argv[])
{
  int quiet_p = argc == 2 && strncmp(argv[1], "--quiet", 8) == 0;
  time_t tloc = 0;
  long retval;
  /* with *tloc == NULL */
  retval = syscall(SYS_time, NULL);
  if (!quiet_p)
    printf("retval = %li\n", retval);
  /* with *tloc != NULL */
  retval = syscall(SYS_time, &tloc);
  if (!quiet_p)
    printf("retval = %li, *tloc = %li\n", retval, tloc);
  return 0;
}
