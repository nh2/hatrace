#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: execve argv0 [argv1...]\n");
  exit(1);
}

int main(int argc, char *const argv[])
{
  if (argc < 2) {
    die_usage();
  }

  char *const envp[] = { NULL };

  execve(argv[1], &argv[1], envp);

  // If execve returns, an error occurred.

  const size_t errmsg_len = sizeof "execve: " + strlen(argv[1]) + 1;
  char errmsg[errmsg_len];
  snprintf(errmsg, errmsg_len, "execve: %s", argv[1]);

  perror(errmsg);

  exit(1);
}
