#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void die_usage(void)
{
 	fprintf(stderr, "Usage: connect [FLAG]\n");
 	exit(1);
}

void connectInet6()
{
	int s;
    struct sockaddr_in6 addr;

    s = socket(AF_INET6, SOCK_STREAM, 0);
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(5000);
    inet_pton(AF_INET6, "::1", &addr.sin6_addr);
    connect(s, (struct sockaddr *)&addr, sizeof(addr));
    close(s);
}


void connectInet()
{
	int s;
    struct sockaddr_in6 addr;

    s = socket(AF_INET6, SOCK_STREAM, 0);
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(5000);
    inet_pton(AF_INET6, "::1", &addr.sin6_addr);
    connect(s, (struct sockaddr *)&addr, sizeof(addr));
    close(s);
}

int main(int argc, char const *argv[])
{
	if (argc != 2){
		die_usage();
	}
	int i = atoi(argv[1]);
	switch(i){
		case AF_INET6:
			connectInet6();
		case AF_INET:
			connectInet();
		default:
			connectInet6();
	}
	/* code */
	return 0;
}
