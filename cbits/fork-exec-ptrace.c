#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ptrace.h>
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>

/* Like the fork() and it uses, on failure this function
   returns -1 and sets errno.
   On success it returns the PID of the child process.

   Failure of ptrace() is currently handled by printing
   with perror() and exiting the child process with code 1.

   Because success of execvp() cannot be observed directly,
   failure of execvp() isn't returned, but printed with perror()
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
    // execvp() denotes end of args by NULL entry.
    char *args [argc+1];
    for (int i=0; i < argc; i++)
      args[i] = argv[i];
    args[argc] = NULL;

    // For PTRACE_TRACEME, all other arguments are ignored.
    long ptrace_retval = ptrace(PTRACE_TRACEME, 0, NULL, NULL);
    if (ptrace_retval != 0)
    {
      perror("ptrace(PTRACE_TRACEME)");
      exit(1);
    }
    kill(getpid(), SIGSTOP);

    int exec_result = execvp(argv[0], args);
    if (exec_result == -1)
    {
      perror("execvp");
      exit(1);
    }
    else
    {
      fprintf(stderr, "BUG: execvp() did not return -1, cannot happen\n");
      exit(1);
    }
  } else {
    // in parent
    return child_pid;
  }

}
