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
  fprintf(stderr, "Usage: sockets <socket | socketpair | sendrecv>\n");
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

void open_socketpair(void)
{
  int socks[2];
  int ret;

  ret = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
  if (ret < 0) {
    perror("socketpair");
    exit(1);
  }

  close(socks[0]);
  close(socks[1]);
}

void open_sendrecv(void)
{
  char buf[500];
  int socks[2];
  int ret;

  ret = socketpair(AF_UNIX, SOCK_STREAM, 0, socks);
  if (ret < 0) {
    perror("socketpair");
    exit(1);
  }

  sendto(socks[0], "pwet\n", 6, 0, NULL, 0);
  recvfrom(socks[1], buf, sizeof(buf), 0, NULL, NULL);

  close(socks[0]);
  close(socks[1]);
}

enum testid {
  TEST_SOCKET = 0,
  TEST_SOCKETPAIR,
  TEST_SENDRECV,
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
  [TEST_SOCKETPAIR] = {
    .name = "socketpair",
    .fct = open_socketpair,
  },
  [TEST_SENDRECV] = {
    .name = "sendrecv",
    .fct = open_sendrecv,
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
