#include <sys/mman.h>
#include <sys/stat.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    char *addr;
    int fd;
    struct stat sb;

    fd = open("example-programs/mmap-syscall.c", O_RDONLY);
    fstat(fd, &sb);

    addr = mmap(NULL, 100, PROT_READ, MAP_SHARED, fd, 0);
    write(STDOUT_FILENO, addr, 100);
    munmap(addr, 100);

    close(fd);
    return 0;
}
