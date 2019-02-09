{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}

module HaTrace
    ( traceForkExec
    , forkExecWithPtrace
    ) where

import Data.Bits ((.|.), (.&.))
import Data.List (find, genericLength)
import Data.Word (Word32, Word64)
import Foreign.C.Types
import Foreign.C.Error (throwErrnoIfMinus1)
import Foreign.Marshal.Array (withArray)
import Foreign.Marshal.Utils (withMany)
import System.Posix.Internals (withFilePath)
import Foreign.Ptr (Ptr)
import GHC.Stack (HasCallStack)

import System.Exit
import System.Linux.Ptrace.Syscall
import System.Linux.Ptrace.Types
import System.Linux.Ptrace.X86Regs
import System.Linux.Ptrace.X86_64Regs
import System.Posix.Signals
import System.Posix.Types
import System.Posix.Waitpid


waitpidForExactPidOrError :: (HasCallStack) => CPid -> IO ()
waitpidForExactPidOrError pid = do
    mr <- waitpid pid []
    case mr of
        Nothing -> error "forkExecWithPtrace: BUG: no PID was returned by waitpid"
        Just (returnedPid, status)
            | returnedPid /= pid -> error $ "forkExecWithPtrace: BUG: returned PID != expected pid: " ++ show (returnedPid, pid)
            | otherwise ->
                case status of
                    Stopped sig | sig == sigSTOP -> return () -- all OK
                    _ -> error $ "forkExecWithPtrace: BUG: unexpected status: " ++ show status


foreign import ccall safe "fork_exec_with_ptrace" c_fork_exec_with_ptrace :: CInt -> Ptr (Ptr CChar) -> IO CPid

-- | Forks a tracee process, makes it PTRACE_TRACEME and then SIGSTOP itself.
-- Waits for the tracee process to have entered the STOPPED state.
-- After waking up from the stop (as controlled by the tracer, that is,
-- other functions you'll use after calling this one),
-- the tracee will execvp() the given program with arguments.
forkExecWithPtrace :: (HasCallStack) => [String] -> IO CPid
forkExecWithPtrace args = do
    childPid <- withMany withFilePath args $ \cstrs -> do
        withArray cstrs $ \argsPtr -> do
            let argc = genericLength args
            throwErrnoIfMinus1 "fork_exec_with_ptrace" $ c_fork_exec_with_ptrace argc argsPtr
    -- Wait for the tracee to stop itself
    waitpidForExactPidOrError childPid
    return childPid


-- TODO Make a version of this that takes a CreateProcess.
--      Note that `System.Linux.Ptrace.traceProcess` isn't good enough,
--      because it is racy:
--      It uses PTHREAD_ATTACH, which sends SIGSTOP to the started
--      process. By that time, the process may already have exited.

traceForkExec :: [String] -> IO ExitCode
traceForkExec args = do
    childPid <- forkExecWithPtrace args
    -- Set `PTRACE_O_TRACESYSGOOD` to make it easy for the tracer
    -- to distinguish normal traps from those caused by a syscall.
    ptrace_setoptions childPid [TraceSysGood]
    let loop state = do
            (newState, exitOrStop) <- waitForSyscall childPid state
            case exitOrStop of
                Left exitCode -> pure exitCode
                Right stopType -> do
                    case stopType of
                        SyscallStop SyscallEnter -> do
                            syscall <- getEnteredSyscall childPid
                            putStrLn $ "Entering syscall: " ++ show syscall
                        SyscallStop SyscallExit -> do
                            putStrLn $ "Exited syscall"
                        SignalDeliveryStop sig -> do
                            printSignal sig
                    loop newState
    loop initialTraceState


-- | The terminology in here is oriented on `man 2 ptrace`.
data SyscallStopType = SyscallEnter | SyscallExit
    deriving (Eq, Ord, Show)


-- | The terminology in here is oriented on `man 2 ptrace`.
data StopType
    = SyscallStop SyscallStopType
    | SignalDeliveryStop Signal
    deriving (Eq, Ord, Show)


-- | Entering and exiting syscalls always happens in turns;
-- we must keep track of that.
--
-- As per `man 2 ptrace`:
--
-- > Syscall-enter-stop and syscall-exit-stop are indistinguishable from each
-- > other by the tracer.
-- > The tracer needs to keep track of the sequence of ptrace-stops in order
-- > to not misinterpret syscall-enter-stop as syscall-exit-stop or vice versa.
-- > The rule is that syscall-enter-stop is always followed by syscall-exit-stop,
-- > PTRACE_EVENT stop or the tracee's death; no other kinds of ptrace-stop
-- > can occur in between.
-- >
-- > If after syscall-enter-stop, the tracer uses a restarting command other than
-- > PTRACE_SYSCALL, syscall-exit-stop is not generated.
--
-- We use this data structure to track it.
data TraceState = TraceState
    { inSyscall :: !Bool -- ^ must be set to false if it's true and the next @ptrace()@ invocation is not @PTRACE_SYSCALL@
    } deriving (Eq, Ord, Show)


initialTraceState :: TraceState
initialTraceState =
    TraceState
        { inSyscall = False
        }


waitForSyscall :: (HasCallStack) => CPid -> TraceState -> IO (TraceState, Either ExitCode StopType)
waitForSyscall pid state@TraceState{ inSyscall } = do
    ptrace_syscall pid Nothing
    mr <- waitpid pid []
    case mr of
        Nothing -> error "waitForSyscall: no PID was returned by waitpid"
        Just (_returnedPid, status) -> do -- TODO must we have different logic if any other pid (e.g. thread, child process of traced process) was returned?
            -- What event occurred; loop if not a syscall or signal
            (newState, exitOrStop) <- case status of
                Exited i -> do
                    case i of
                        0 -> pure (state, Left ExitSuccess)
                        _ -> pure (state, Left $ ExitFailure i)
                Continued -> waitForSyscall pid state
                Signaled sig -> pure (state, Right $ SignalDeliveryStop sig)
                Stopped sig
                    | sig == (sigTRAP .|. 0x80) -> if
                        | inSyscall -> pure (state{ inSyscall = False }, Right $ SyscallStop SyscallExit)
                        | otherwise -> pure (state{ inSyscall = True }, Right $ SyscallStop SyscallEnter)
                    | otherwise -> waitForSyscall pid state

            return (newState, exitOrStop)

printSignal :: Signal -> IO ()
printSignal s =
    case find (\(a, _, _) -> s == a) ls of
        Nothing -> putStrLn $ "Unknown signal: " ++ show s
        Just (_, n1, n2) -> do
            print (n1, n2)
  where
    ls =
        [ (nullSignal, "nullSignal", "NULL")
        , (internalAbort, "internalAbort", "ABRT")
        , (realTimeAlarm, "realTimeAlarm", "ALRM")
        , (busError, "busError", "BUS")
        , (processStatusChanged, "processStatusChanged", "CHLD")
        , (continueProcess, "continueProcess", "CONT")
        , (floatingPointException, "floatingPointException", "FPE")
        , (lostConnection, "lostConnection", "HUP")
        , (illegalInstruction, "illegalInstruction", "ILL")
        , (keyboardSignal, "keyboardSignal", "INT")
        , (killProcess, "killProcess", "KILL")
        , (openEndedPipe, "openEndedPipe", "PIPE")
        , (keyboardTermination, "keyboardTermination", "QUIT")
        , (segmentationViolation, "segmentationViolation", "SEGV")
        , (softwareStop, "softwareStop", "STOP")
        , (softwareTermination, "softwareTermination", "TERM")
        , (keyboardStop, "keyboardStop", "TSTP")
        , (backgroundRead, "backgroundRead", "TTIN")
        , (backgroundWrite, "backgroundWrite", "TTOU")
        , (userDefinedSignal1, "userDefinedSignal1", "USR1")
        , (userDefinedSignal2, "userDefinedSignal2", "USR2")
        , (pollableEvent, "pollableEvent", "POLL")
        , (profilingTimerExpired, "profilingTimerExpired", "PROF")
        , (badSystemCall, "badSystemCall", "SYS")
        , (breakpointTrap, "breakpointTrap", "TRAP")
        , (urgentDataAvailable, "urgentDataAvailable", "URG")
        , (virtualTimerExpired, "virtualTimerExpired", "VTALRM")
        , (cpuTimeLimitExceeded, "cpuTimeLimitExceeded", "XCPU")
        , (fileSizeLimitExceeded, "fileSizeLimitExceeded", "XFSZ")
        ]

data Syscall
    = Read
    | Write
    | Execve
    | Exit
    | UnknownSyscall !Word64
    deriving (Show, Eq)


-- TODO Get this from kernel headers
__X32_SYSCALL_BITMASK :: Word64
__X32_SYSCALL_BITMASK = 0x40000000


syscallNumberToName_i386 :: Word32 -> Syscall
syscallNumberToName_i386 = \case
    1 -> Exit
    3 -> Read
    4 -> Write
    11 -> Execve
    i -> UnknownSyscall (fromIntegral i)


syscallNumberToName_x64_64 :: Word64 -> Syscall
syscallNumberToName_x64_64 = \case
    0 -> Read
    1 -> Write
    59 -> Execve
    60 -> Exit
    i -> UnknownSyscall i


getEnteredSyscall :: CPid -> IO Syscall
getEnteredSyscall cpid = do
    regs <- ptrace_getregs cpid
    pure $ case regs of
        X86 X86Regs{ orig_eax } -> do
            syscallNumberToName_i386 orig_eax
        X86_64 X86_64Regs{ orig_rax } -> do
            -- TODO This works only for x32, but not for i386. Figure it out!
            -- Apparenlty strace on Ubuntu 16.04 also gets it wrong (I tried it).
            -- This also confirms that strace gets it wrong:
            --     https://stackoverflow.com/questions/46087730/what-happens-if-you-use-the-32-bit-int-0x80-linux-abi-in-64-bit-code
            -- Unanswered question on how to detect it:
            --     https://superuser.com/questions/834122/how-to-distinguish-syscalls-form-int-80h-when-using-ptrace
            -- Maybe it's impossible?
            -- The presentation at
            --     https://www.linuxplumbersconf.org/event/2/contributions/78/attachments/63/74/lpc_2018-what_could_be_done_in_the_kernel_to_make_strace_happy.pdf
            -- suggests it's impossible ("There is no reliable way to distinguish between x86_64 and x86 syscalls").
            -- A solution was proposed: https://lwn.net/Articles/772894/
            -- But `clever` from IRC suggests:
            -- > strace is using the same api as gdb, so it should be trivial to just look at the instructions the return address points to, and see what it was
            let is_x32_bitMode = (orig_rax .&. __X32_SYSCALL_BITMASK) /= 0

            -- TODO Check if we should implement special treatment for syscall number -1,
            -- like strace does in
            --     https://github.com/strace/strace/blob/2c8b6de913973274e877639658e9e7273a012adb/linux/x86_64/get_scno.c#L43
            if is_x32_bitMode
                then syscallNumberToName_i386 (fromIntegral orig_rax)
                else syscallNumberToName_x64_64 orig_rax
