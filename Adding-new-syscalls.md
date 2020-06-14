# Addding new syscalls to hatrace

Adding a new syscall definitions to `hatrace` is relatively simple and looks more or less the same for all of them. And yet different syscalls have different arguments and require different ways of handling them. The starting point could be just opening a man page in section 2 for a particular syscall - for example `man 2 unlink`. On that man page you should be able to find all the details you need and usually you'll get details not for just one syscall but also for some related syscalls as well. It makes sense to implement all of them as one PR.

`hatrace` catches 2 events related to a syscall invocation:
* syscall enter
* syscall exit

Those two events need different handling because a syscall could fill some data as its side effect so on enter that argument could be not yet initialized.

## Enter details

Every syscall supported by `hatrace` defines a new record type with its details. These details normally should contain original C arguments and for user convenience also some peeked details like for example `ByteString` value if a syscall takes a `char*` argument. For the syscall `unlink` this type will have name `SyscallEnterDetails_unlink`. This details record should be added as a new constructor `DetailedSyscallEnter_unlink` of the aggregate type `DetailedSyscallEnter`.
These details get filled in the function `getSyscallEnterDetails` in a case clause corresponding to a syscall. For `unlink` case clause should match `Syscall_unlink`.
For proper enter details output formatting one needs to do 2 things:
* add an instance of type class `SyscallEnterFormatting` for enter details record
* add a corresponding case of a form `DetailedSyscallEnter_foo details -> syscallEnterToFormatted details` into the function `formatSyscallEnter`

For formatting details see the module `System.Hatrace.Format`

## Exit details

Just like with enter details every syscall needs its exit details defined. Their main purpose is to store values filled by a syscall alongside with syscall enter details. Exit details need to be defined as a record named `SyscallExitDetails_XXX` where `XXX` is a syscall name, so for `unlink` we'll have `SyscallExitDetails_unlink`. This record will get stored as a field in a new constructor of the `DetailedSyscallExit` data type and for `unlink` such a constructor name will be `DetailedSyscallExit_unlink`.
In the function `getSyscallExitDetails` these details get filled after matching an enter details constructor.
Formatting of exit details is done using the type class `SyscallExitFormatting` in `formatDetailedSyscallExit`.

## Dealing with syscall parameters

Currently the most of primitive syscall arguments are just represented as `CInt`s but there is some support for more complex types. For the types represented as `CInt` there is a type class `CIntRepresentable` with conversion methods `fromCInt` and `toCInt`. And for output formatting there is a type class `ArgFormatting`. In most cases types stored in a `CInt` could be classified into 2 categories: 1) enumerations of some values; 2) flags which could be combined together. Implementing `CIntRepresentable` and `ArgFormatting` for such types is quite repetitive and a bit error-prone as some values could be hidden behind `#ifdef`s. Because of that `hatrace` has some Template Haskell helpers deriving needed instances automatically. See their haddocks in `System.Hatrace.Types.TH`.

String values are represented in 2 forms:
* `Ptr CChar` as a raw value mirroring `char*` in C
* `ByteString` with a value peeked from the pointer above, this could be a field of either enter or exit details depending on whether it's specified by a user or if the kernel provides it

For handling C structs see some examples in the module `System.Hatrace.Types`.

## Implementation checklist

So in general to add a new syscall `foo` to `hatrace` one needs to do the following:

0. (Optional) Add custom types for marshalling complex argument types to the module `System.Hatrace.Types` if those are required:
    1. Add or edit a new describe procedure.
    2. Validate running `stack test --ta "-m XXX"` where XXX match the modified describe procedure.
1. **Enter** details:
    1. Create data type `SyscallEnterDetails_foo`.
    2. Add an entry for it in the type `DetailedSyscallEnter` sum type.
    3. Update `getSyscallEnterDetails` accordingly (add above _unknown).
    4. Add an instance of `SyscallEnterFormatting` and update `formatSyscallEnter` accordingly.
2. **Exit** details:
    1. Create data type `SyscallExitDetails_foo`.
    2. Add an entry for it the type `DetailedSyscallExit` sum type.
    3. Update `getSyscallExitDetails` accordingly.
    4. Add an instance of `SyscallExitFormatting` and update `formatDetailedSyscallExit` accordingly.
3. (Optional but highly recommended) Add test(s) for the implemented syscall - see `HatraceSpec` for examples
