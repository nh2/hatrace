#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>

int main() {
    char *addr;
    int fd;
    struct stat sb;

    fd = open("example-programs/mmap-syscall.c", O_RDONLY);
    if (fd == -1) {
        perror("open");
        return 1;
    }
    if (fstat(fd, &sb) == -1) {
        perror("open");
        return 1;
    }

    addr = mmap(NULL, 100, PROT_READ, MAP_SHARED, fd, 0);
    printf("%d\n", MAP_SHARED);
    if (addr == (void*)-1) {
        perror("mmap");
        return 1;
    }
    if (write(STDOUT_FILENO, addr, 100) == -1) {
        perror("write");
        return 1;
    }
    if (munmap(addr, 100) == -1) {
        perror("munmap");
        return 1;
    }

    if (close(fd) == -1) {
        perror("close");
        return 1;
    }
    return 0;
}
