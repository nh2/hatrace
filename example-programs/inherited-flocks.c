#include <errno.h>
#include <stdio.h>
#include <sys/file.h>
#include <unistd.h>
#include <pthread.h> 

void *myThreadFun(void *vargp) {
  // Store the value argument passed to this thread 
  int fd = *((int *)vargp); 

  printf("Thread started, got passed fd %d\n", fd);

  sleep(2);

  puts("Thread exiting\n");

  return 0;
}

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

  pthread_t tid;
  int ret = pthread_create(&tid, NULL, myThreadFun, (void *)&fd);

  if (ret != 0) {
    errno = ret; // pthread_create() does not set errno, but returns it
    perror("pthread_create");
    return 3;
  }

  printf("Main started side thread; closing FD %d to unlock, and sleeping for 1 second\n", fd);

  close(fd);

  sleep(1);

  puts("Main re-opening and re-locking file");

  fd = open(filepath, O_RDWR);

  if (fd < 0) {
    perror("open");
    return 1;
  }

  if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
    perror("flock");
    return 2;
  }

  pthread_exit(NULL); // exit main thread and wait for all threads to finish

  return 0;
}
