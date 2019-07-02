#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/poll.h>

#define TIMEOUT 5

void die_usage(void) {
  fprintf(stderr, "Usage: poll file\n");
  exit(1);
}

int main (int argc, char const *argv[]) {
  if (argc < 1) {
    die_usage();
  }

  struct pollfd fds[3];
  int ret;
  int fd = open(argv[1], O_RDWR);

  if (fd < 0) {
    perror("could not open provided file");
    return 1;
  }

  /* watch stdout for ability to write */
  fds[0].fd = STDOUT_FILENO;
  fds[0].events = POLLHUP | POLLOUT | POLLIN;

  fds[1].fd = STDIN_FILENO;
  fds[1].events = POLLIN;

  fds[2].fd = fd;
  fds[2].events = POLLIN | POLLOUT;

  ret = poll(fds, 3, TIMEOUT * 1000);

  if (ret == -1) {
    perror("poll returned error");
    return 1;
  }

  if (!ret) {
    perror("poll timed out before stdout was available for write");
    return 1;
  }

  if (fds[0].revents & POLLOUT) {
    return 0;
  }

  perror("poll returned success response, but stdout is not available for write");
  return 1;

}

