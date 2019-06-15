#include <stdio.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>

void socket_ok(int sock)
{
	if (sock < 0) {
		perror("socket");
		exit(1);
	}

	close(sock);
}

void socket_fail(int sock)
{
	if (sock >= 0) {
		close(sock);
		exit(1);
	}
}

void die_usage(void)
{
	fprintf(stderr, "Usage: sockets\n");
	exit(1);
}

void open_sockets(void)
{
	int sock;

	sock = socket(AF_INET, SOCK_STREAM, 0);
	socket_ok(sock);

	sock = socket(AF_INET6, SOCK_STREAM, 0);
	socket_ok(sock);

	sock = socket(AF_INET, SOCK_DGRAM, 0);
	socket_ok(sock);

	sock = socket(AF_INET6, SOCK_DGRAM, 0);
	socket_ok(sock);

	sock = socket(AF_UNIX, SOCK_STREAM, 0);
	socket_ok(sock);

	sock = socket(AF_UNIX, SOCK_DGRAM, 0);
	socket_ok(sock);

	sock = socket(AF_UNSPEC, SOCK_DGRAM, 0);
	socket_fail(sock);

	sock = socket(AF_MAX + 10, SOCK_DGRAM, 0);
	socket_fail(sock);

	sock = socket(AF_INET, -1, 0);
	socket_fail(sock);

	sock = socket(AF_INET, 40, 0);
	socket_fail(sock);
}

enum testid {
	TEST_SOCKET = 0,
	TEST_MAX,
};

struct testdesc {
	char *name;
	void (*fct)(void);
};

struct testdesc tests[TEST_MAX] = {
	[TEST_SOCKET] = {
		.name = "socket",
		.fct = open_sockets,
	},
};

int main(int argc, char **argv)
{
	int i;

	if (argc != 2)
		die_usage();

	for (i = 0; i < TEST_MAX; i++) {
		if (strcmp(argv[1], tests[i].name) == 0)
			break;
	}

	if (i == TEST_MAX)
		die_usage();

	tests[i].fct();

	return 0;
}
