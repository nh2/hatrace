[![CircleCI](https://circleci.com/gh/nh2/hatrace.svg?style=svg)](https://circleci.com/gh/nh2/hatrace)

# hatrace - scripted `strace`

Includes:

* `hatrace` executable similar to [`strace`](https://strace.io/)
* Haskell library to write sophisticated scripts

## Use cases

* **General**
  * Get all syscalls in a list and process them programatically.
  * Audit high-assurance software systems.
  * Debug difficult bugs that occur only in certain rare situations.
  * Change the results of system calls as seen by the traced program.
* **Bug reproducers**
  * Demonstrate how a program fails when a given syscall returns certain data.
  * Kill your build tool at the 3rd `write()` syscall to an `.o` file, checking whether it will recover from that in the next run.
* **Testing**
  * Write test suites that assert how your code uses system calls, for correctness or performance.
  * Mock syscalls to test how your program would behave in situations that are difficult to create in the real world.
  * Implement anomaly test suites [like `sqlite` does](https://www.sqlite.org/testing.html#i_o_error_testing), exhaustively testing whether your program can recover from a crash in _any_ syscall.
* **Fuzzing**
  * Insert garbage data into the program by changing syscall results or directly changing its memory contents.
  * Speed up your fuzzing by having full insight into the fuzzed program's behaviour.
* **Adding features to existing programs**
  * Add "magic" support for new file systems without modifying existing programs (like [this paper](https://www.usenix.org/legacy/events/expcs07/papers/22-spillane.pdf) shows).
  * Add logging capabilities to programs that were designed without.

## Work in progress

This software is work in progress.

The `hatrace` executable is extremely basic and can't do much.

While syscall names are automatically generated, detail data needs to be implemented by hand and is done for only a few so far.
Help to add more is appreciated.

However, the Haskell API to write scripts can already do a log. Take a look at the test suite for examples.

### TODO list for contributors

If you find any of the below topics interesting give it a shot!
It is recommended to file an issue when picking up one of the tasks to coordinate against doing duplicate work.

* [ ] Implement all the syscalls
* [ ] Remembering syscall arguments in a PID/TID map
* [ ] Support for `sysenter`
* [ ] reading tracee memory more efficiently (see [how strace does it](https://github.com/strace/strace/blob/d091f1a9e27756b3c399da1c500c915f473a56f3/ucopy.c#L45)
* [ ] Helpers for modifying memory
* [ ] One real-world example each for the use cases on `Use cases` above
* [ ] `hatrace` executable features:
  * [ ] JSON output
  * [ ] Coloured output
  * [ ] Timing `strace -ttt` and `-T`
  * [ ] special run modes tailored to specific tasks (e.g. execve tree)
    * [ ] Show hanging syscalls
    * [ ] Filter away GHC's spammy output around `sched_yield`, `futex` and signals
* [ ] Support for setting options (for example enabling/disabling tracing into subprocesses, like `strace -f`)
* [ ] Equivalent to `strace -y` (tracking origin of file descriptors, printing paths)
* [ ] Equivalent to `strace -c` (keeping counts, summary statistics)
* [ ] Something similar to `strace -y` but telling which PID is which executable from `/proc/PID/exe`
* [ ] Extraction of `PTRACE_EVENT` detail information (see section `PTRACE_SETOPTIONS` in `man 2 ptrace`)
* [ ] Filtering based on string buffer contents
* [ ] PID remapping (e.g. to a range starting from 0) for better diffability of the output of multiple runs
* [ ] Handling of `exit()` of the direct child (grand-child daemonisation)
* [ ] Don't die on `peekBytes` returning `EIO` when the tracee passes invalid memory to the kernel; instead, peek only what's possible and print some info. That makes it possible to correctly trace processes that rely on e.g. `SIGSEGV` handlers.
* [ ] Re-using strace's test suite for per-syscall tests
* [ ] other TODOs in the code
* Use it to do specific investigations in other programs:
  * [ ] investigate [big GHC linker speed differences](https://github.com/nh2/hatrace/pull/9#issuecomment-477573945)
