#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>

int main() {
	dup3(0, 1, O_CLOEXEC);
	dup3(0, 1, 0);
}
