#include <stdio.h>
#include <stdlib.h>
#include <sys/sysinfo.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: sysinfo-loads\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc > 1) {
    die_usage();
  }
  struct sysinfo info;
  int res = sysinfo(&info);
  if (res == -1) {
    perror("sysinfo");
    exit(1);
  }

  float f_load = 1.f / (1 << SI_LOAD_SHIFT);
  
  printf("load avg 1 minute: %.2f%% CPU\n"
	 "load avg 5 minutes: %.2f%% CPU\n"
	 "load avg 15 minuites: %.2f%% CPU\n",
	 info.loads[0] * f_load * 100,
	 info.loads[1] * f_load * 100,
	 info.loads[2] * f_load * 100);
  return 0;
}
