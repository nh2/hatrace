#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: atomic-write [atomic|non-atomic] NUM_BYTES FILE\n");
  exit(1);
}

void do_write(const char* file, size_t numBytes, bool atomic)
{
  // If atomic, write to a temp file first, then move it.
  const char *ext = ".tmp";
  const size_t pathLen = strlen(file) + strlen(ext) + 1;
  char path[pathLen];
  snprintf(path, pathLen, "%s%s", file, atomic ? ext : "");

  // Open
  int fd = open(path, O_CREAT | O_TRUNC | O_WRONLY, S_IRUSR | S_IWUSR);
  if (fd == -1) {
    perror("open");
    exit(1);
  }

  // Write numBytes many 'a's to the file.
  size_t written = 0;
  while (written < numBytes) {
    size_t res = write(fd, "a", 1);
    if (res == -1) {
      if (errno == EINTR) {
        continue;
      } else {
        perror("write");
        exit(1);
      }
    }
    written += res;
  }
  // Close
  if(close(fd) != 0) {
    perror("close");
    exit(1);
  }

  // If atomic, do the rename.
  if (atomic) {
    if (rename(path, file) != 0) {
      perror("rename");
      exit(1);
    }
  }
}

int main(int argc, char const *argv[])
{
  if (argc != 4) {
    die_usage();
  }

  // Parse atomic argument
  bool atomic;
  if (strcmp(argv[1], "atomic") == 0) {
    atomic = true;
  } else if (strcmp(argv[1], "non-atomic") == 0) {
    atomic = false;
  } else {
    die_usage();
  }

  // Parse NUM_BYTES argument
  const char *string_to_parse = argv[2];
  errno = 0;
  char * endptr = NULL;
  size_t numBytes = strtoul(string_to_parse, &endptr, 0); // base=0 for auto-detection
  // Failure detection:
  // 1. `endptr == string_to_parse` indicates there was no number at all in the string.
  // 2. `errno == ERANGE` indicates a numerical overflow.
  // 3. `*endptr != \0` indicates that not the entire string was parsed (leading whitespace is still allowed)
  if (endptr == string_to_parse || errno == ERANGE || *endptr != '\0') {
    fprintf(stderr, "Bad NUM_BYTES value: %s\n", argv[2]);
    exit(1);
  }

  // Parse FILE argument
  const char *file = argv[3];

  printf("Writing %zu bytes %satomically to %s\n", numBytes, atomic ? "" : "non-", file);

  do_write(file, numBytes, atomic);

  return 0;
}
