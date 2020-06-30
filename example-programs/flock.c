#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>

int main(int argc, char* argv[]) {
  if (argc != 2) {
    puts("flock /path/to/file/to/lock\n");
    return 1;
  }

  const char* filepath = argv[1];

  int fd = open(filepath, O_RDWR);

  if (fd < 0) {
    perror("open");
    return 1;
  }

  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    perror("flock");
    return 2;
  }

  return 0;
}
