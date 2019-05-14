#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <signal.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

// On Linux the request is `PTRACE_TRACEME`,
// on other platforms it is `PT_TRACE_ME`.
// (Although modern implementations of libc define both.)
#ifndef PT_TRACE_ME
  #define PT_TRACE_ME PTRACE_TRACEME
#endif

// On Linux the `data` parameter has type `void *`,
// on other platforms it is an `int`.
#if __linux__
  #define PTRACE_EMPTY_DATA NULL
#else
  #define PTRACE_EMPTY_DATA 0
#endif

/* Like the fork() and it uses, on failure this function
   returns -1 and sets errno.
   On success it returns the PID of the child process.

   Failure of ptrace() is currently handled by printing
   with perror() and exiting the child process with code 1.

   Because success of execv() cannot be observed directly,
   failure of execv() isn't returned, but printed with perror()
   and the child process exits with code 1.
 */
pid_t fork_exec_with_ptrace(int argc, char **argv)
{
  pid_t child_pid = fork();

  if (child_pid == -1)
    return -1;

  if (child_pid == 0) {
    // in child

    // Prepare child args.
    // execv() denotes end of args by NULL entry.
    char *args [argc+1];
    for (int i=0; i < argc; i++)
      args[i] = argv[i];
    args[argc] = NULL;

    // For PTRACE_TRACEME, all other arguments are ignored.
    long ptrace_retval = ptrace(PT_TRACE_ME, 0, NULL, PTRACE_EMPTY_DATA);
    if (ptrace_retval != 0)
    {
      perror("ptrace(PTRACE_TRACEME)");
      exit(1);
    }
    // We use the syscall directly here, as opposed to e.g.
    // libc's `raise()`, to guarantee consistent behaviour.
    // The only thing that `raise()` would do for us is to
    // handle the case where we are multi-threaded, using
    // `pthread_kill()` in that case, but we are directly
    // after `fork()` here so we know there's only 1 thread.
    kill(getpid(), SIGSTOP);

    // We use execv() instead of execvp() because we don't
    // want the latter's /bin/sh fallback.
    int exec_result = execv(argv[0], args);
    if (exec_result == -1)
    {
      perror("execv");
      exit(1);
    }
    else
    {
      fprintf(stderr, "BUG: execv() did not return -1, cannot happen\n");
      exit(1);
    }
  } else {
    // in parent
    return child_pid;
  }

}
