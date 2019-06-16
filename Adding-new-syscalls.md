# Addding new syscalls to hatrace

Adding a new syscall definitions to `hatrace` is relatively simple and looks more or less the same for all of them. And yet different syscalls have different arguments and require different ways of handling them. The starting point could be just opening a man page in section 2 for a particular syscall - for example `man 2 unlink`. On that man page you should be able to find all the details you need and usually you'll get details not for just one syscall but also for some related syscalls as well. It makes sense to implement all of them as one PR.

`hatrace` catches 2 events related to a syscall invocation:
	* syscall enter
	* syscall exit

Those two events need different handling because a syscall could fill some data as its side effect so on enter that argument could be not yet initialized.

## Enter details

Every syscall supported by `hatrace` defines a new record type with its details. These details normally should contain original C arguments and for user convenience also some peeked details like for example `ByteString` value if a syscall takes a `char*` argument. For the syscall `unlink` this type will have name `SyscallEnterDetails_unlink`. This details record should be added as a new constructor `DetailedSyscallEnter_unlink` of the aggregate type `DetailedSyscallEnter`.
These details get filled in the function `getSyscallEnterDetails` in a case clause corresponding to a syscall. For `unlink` case clause should match `Syscall_unlink`.
Current output of syscalls is done in `formatDetailedSyscallEnter` so to make `hatrace` output particular syscall details a new case clause should be added there. The clause should use previously created details constructor, in case of `unlink` it will be `DetailedSyscallEnter_unlink`. 

## Exit details

Just like with enter details every syscall needs its exit details defined. Their main purpose is to store values filled by a syscall alongside with syscall enter details. Exit details need to be defined as a record named `SyscallExitDetails_XXX` where `XXX` is a syscall name, so for `unlink` we'll have `SyscallExitDetails_unlink`. This record will get stored as a field in a new constructor of the `DetailedSyscallExit` data type and for `unlink` such a constructor name will be `DetailedSyscallExit_unlink`.
In the function `getSyscallExitDetails` these details get filled after matching an enter details constructor.
Formatting of exit details is done in `formatDetailedSyscallExit`

## Dealing with syscall parameters

Currently the most of primitive syscall arguments are just represented as `CInt`s but there is some support for more complex types, see some examples in the module `System.Hatrace.Types`.
TODO: describe handling of complex structs as well as dealing with strings.

## Implementation checklist

So in general to add a new syscall `foo` to `hatrace` one needs to do the following:

0. (Optional) Add custom types for marshalling complex argument types to the module `System.Hatrace.Types` if those are required.
1. **Enter** details:
    1. Create data type `SyscallEnterDetails_foo`.
    2. Add an entry for it in the type `DetailedSyscallEnter` sum type.
    3. Update `getSyscallEnterDetails` accordingly.
    4. Update `formatDetailedSyscallEnter` accordingly.
2. **Exit** details:
    1. Create data type `SyscallExitDetails_foo`.
    2. Add an entry for it the type `DetailedSyscallExit` sum type.
    3. Update `getSyscallExitDetails` accordingly.
    4. Update `formatDetailedSyscallExit` accordingly.
3. (Optional but highly recommended) Add test(s) for the implemented syscall - see `HatraceSpec` for examples
