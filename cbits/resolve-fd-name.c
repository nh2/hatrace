#include <errno.h>
#include <sys/param.h>

#ifdef __linux__
#include <stdio.h>
#include <unistd.h>
#else
#include <libproc.h>
#include <memory.h>
#endif

// assert: sizeof(buf) == MAXPATHLEN
// return:
//   * -1 = see errno
//   *  0 = ok
//   *  1 = File does not exist
//   *  2 = Something terrible happened
int resolve_fd_name(int pid, int fd, char buf[]) {

#if defined __linux__

  char proc_path[MAXPATHLEN];
  snprintf(proc_path, MAXPATHLEN, "/proc/%d/fd/%d", pid, fd);

  int bytes = readlink(proc_path, buf, MAXPATHLEN - 1);
  if (bytes < 0) {
    return -1;
  }

  buf[bytes] = '\0';

  return 0;

#elif defined __APPLE__

  struct vnode_fdinfowithpath vi;

  int nb = proc_pidfdinfo(pid, fd, PROC_PIDFDVNODEPATHINFO, &vi, sizeof(vi));

  if (nb <= 0) {
    if (errno == ENOENT) {
      return 1;
    } else {
      return -1;
    }
  } else if (nb != sizeof(vi)) {
    return 2;
  }

  memcpy(buf, vi.pvip.vip_path, MAXPATHLEN);

  return 0;

#else

  return 2

#endif

}
