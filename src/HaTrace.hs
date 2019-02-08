{-# LANGUAGE RecordWildCards #-}

module HaTrace
    ( traceForkExec
    , forkExecWithPtrace
    ) where

import Data.List (find, genericLength)
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
    let loop = do
            exitOrSignal <- waitForSyscall childPid
            case exitOrSignal of
                Left ec -> pure ec
                Right s -> do
                    printSignal s
                    printSyscall childPid
                    loop
    loop


waitForSyscall :: (HasCallStack) => CPid -> IO (Either ExitCode Signal)
waitForSyscall pid = do
    ptrace_syscall pid Nothing
    mr <- waitpid pid []
    case mr of
        Nothing -> error "waitForSyscall: no PID was returned by waitpid"
        Just (_returnedPid, status) -> -- TODO must we have different logic if any other pid (e.g. thread, child process of traced process) was returned?
            case status of
                Exited i -> do
                    case i of
                        0 -> pure $ Left ExitSuccess
                        _ -> pure $ Left $ ExitFailure i
                Continued -> waitForSyscall pid
                Signaled sig -> pure $ Right sig
                Stopped sig -> pure $ Right sig

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

printSyscall :: CPid -> IO ()
printSyscall cpid = do
    regs <- ptrace_getregs cpid
    case regs of
        X86 x86Regs -> printX86Regs x86Regs
        X86_64 x86_64Regs -> printX86_64Regs x86_64Regs

printX86Regs :: X86Regs -> IO ()
printX86Regs = print

printX86_64Regs :: X86_64Regs -> IO ()
printX86_64Regs r =
    case parseSyscall r of
        Nothing -> putStrLn $ "Unknown syscall number: " ++ show (orig_rax r)
        Just sc -> print sc

data Syscall
    = Read
    | Write
    deriving (Show, Eq)

parseSyscall :: X86_64Regs -> Maybe Syscall
parseSyscall X86_64Regs {..} =
    case orig_rax of
        0x3 -> Just Read
        0x4 -> Just Write
        _ -> Nothing
