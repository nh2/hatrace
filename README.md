# hatrace - scripted strace

Includes:

* `hatrace` executable similar to [`strace`](https://strace.io/)
* Haskell library to write sophisticated scripts

## Use cases

* Get all syscalls in a list and process them programatically.
* Audit high-assurance software systems.
* Debug difficult bugs that occur only in certain rare situations.
* Kill your build tool at the 3rd `write()` syscall to an `.o` file, checking whether it will recover from that in the next run.
* Change the results of system calls as seen by the traced program.
  * Mock syscalls to test how your program would behave in situations that are difficult to create in the real world.
  * Add "magic" support for new file systems without modifying existing programs (like [this paper](https://www.usenix.org/legacy/events/expcs07/papers/22-spillane.pdf) shows)
* Implement anomaly test suites [like `sqlite` does](https://www.sqlite.org/testing.html#i_o_error_testing), exhaustively testing whether your program can recover from a crash in _any_ syscall

## Work in progress

This software is work in progress.

The `hatrace` executable is extremely basic and can't do much.

While syscall names are automatically generated, detail data needs to be implemented by hand and is done for only a few so far.
Help to add more is appreciated.

However, the Haskell API to write scripts can already do a log. Take a look at the test suite for examples.
