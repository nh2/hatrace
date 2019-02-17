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
  * Add logging capabilities to prgrams that were designed without.

## Work in progress

This software is work in progress.

The `hatrace` executable is extremely basic and can't do much.

While syscall names are automatically generated, detail data needs to be implemented by hand and is done for only a few so far.
Help to add more is appreciated.

However, the Haskell API to write scripts can already do a log. Take a look at the test suite for examples.
