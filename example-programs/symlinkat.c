#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

void die_usage(void)
{
  fprintf(stderr, "Usage: symlinkat target directory linkpath\n");
  exit(1);
}

int main(int argc, char const *argv[])
{
  if (argc < 2) {
    die_usage();
  }

  char template[] = "/tmp/symlinkat.tmpdir.XXXXXX";
  char *tmp_dirname = mkdtemp (template);

  if(tmp_dirname == NULL) {
     perror ("could not create tmp directory");
     exit (EXIT_FAILURE);
  }

  int dirfd = open(tmp_dirname, O_DIRECTORY | O_RDONLY);
  if (dirfd == -1) {
    perror("could not get file descriptor for directory");
    exit (EXIT_FAILURE);
  }

  int res = symlinkat(argv[1], dirfd, argv[2]);
  if (res == -1) {
    perror("symlinkat failed");
    exit(EXIT_FAILURE);
  }

  return 0;
}
