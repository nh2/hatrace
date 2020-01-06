#define _POSIX_SOURCE
#include <sys/types.h>
#include <signal.h>
#include <unistd.h>

int main (int argc, char const *argv[]) {
  signal(SIGUSR1, SIG_IGN);
  kill(getpid(), SIGUSR1);
  return 0;
}

