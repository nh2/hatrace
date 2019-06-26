#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <linux/netlink.h>
#include <linux/un.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>

void die_usage(void){
 	fprintf(stderr, "Usage: connect [FLAG]\n");
 	exit(1);
}

void error_connect(void){
    printf("\n Error: Could not connect to socket.");
    exit(1);
}

void connectInet6(){
	int sockfd = socket(AF_INET6, SOCK_STREAM, 0);
 	if(sockfd < 0){
        printf("\n Error : Could not create Inet6 socket \n");
        exit(1);
    }
    struct sockaddr_in6 addr;
    addr.sin6_family = AF_INET6;
    addr.sin6_port = htons(5000);
    inet_pton(AF_INET6, "::1", &addr.sin6_addr);
    if(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0){
        error_connect();
    }
    close(sockfd);
}


void connectInet(){
 	int sockfd = socket(AF_INET, SOCK_STREAM, 0);
 	if(sockfd < 0){
        printf("\n Error : Could not create Inet socket \n");
        exit(1);
    }
    struct sockaddr_in addr;
    addr.sin_family = AF_INET;
    if(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0){
        error_connect();
    }
    close(sockfd);
}

void connectNetlink(){
	int sockfd = socket(PF_NETLINK, SOCK_RAW, 0);
	if(sockfd < 0){
		printf("\n Error: Could not create netlink socket \n");
		exit(1);
	}
	struct sockaddr_nl addr;
	addr.nl_family = AF_NETLINK;
    addr.nl_pid = getpid(); /* self pid */
	if(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0){
        error_connect();
    }
	close(sockfd);
}

void connectUnix(){
	int sockfd = socket(PF_UNIX, SOCK_STREAM, 0);
	if(sockfd < 0){
		printf("\n Error: Could not create unix socket \n");
		exit(1);
	}
	struct sockaddr_un addr;
	memset(&addr, 0, sizeof(struct sockaddr_un));
	addr.sun_family = AF_UNIX;
	snprintf(addr.sun_path, UNIX_PATH_MAX, "./demo_socket");
 	if(connect(sockfd, (struct sockaddr *)&addr, sizeof(addr)) != 0){
        error_connect();
    }
}

void connectPacket(){
	/* TODO: implement connect call for packet socket */
}

int main(int argc, char const *argv[]){
	if (argc != 2){
		die_usage();
	}
	int i = atoi(argv[1]);
	switch(i){
		case AF_UNIX:
			connectUnix();
			break;
		case AF_INET:
			connectInet();
			break;
		case AF_INET6:
			connectInet6();
			break;
		case AF_PACKET:
			connectPacket();
			break;
		case AF_NETLINK:
			connectNetlink();
			break;
		default:
			die_usage();
	}
	/* code */
	return 0;
}
