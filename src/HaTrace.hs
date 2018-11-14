{-# LANGUAGE RecordWildCards #-}

module HaTrace
    ( traceCreateProcess
    -- * Re-exports
    , module System.Process
    , ExitCode(..)
    ) where

import Control.Concurrent.MVar
import Data.List (find)

import System.Exit
import System.Linux.Ptrace
import System.Linux.Ptrace.Syscall
import System.Linux.Ptrace.Types
import System.Linux.Ptrace.X86_64Regs
import System.Posix.Signals
import System.Posix.Types
import System.Posix.Waitpid
import System.Process
import System.Process.Internals

traceCreateProcess :: CreateProcess -> IO ExitCode
traceCreateProcess cp = do
    (_, _, _, ph) <- createProcess cp
    case ph of
        ProcessHandle mvar b -> do
            ph__ <- readMVar mvar
            case ph__ of
                ClosedHandle ec -> pure ec
                OpenHandle cpid -> do
                    tp <- traceProcess cpid
                    let loop = do
                            exitOrSignal <- waitForSyscall cpid
                            case exitOrSignal of
                                Left ec -> pure ec
                                Right s -> do
                                    printSignal s
                                    printSyscall cpid
                                    loop
                    loop

waitForSyscall :: CPid -> IO (Either ExitCode Signal)
waitForSyscall cpid = do
    ptrace_syscall cpid Nothing
    mr <- waitpid cpid []
    case mr of
        Nothing -> error "No idea what this means."
        Just (_, s) -- TODO what does this first part do?
         ->
            case s of
                Exited i -> do
                    case i of
                        0 -> pure $ Left ExitSuccess
                        _ -> pure $ Left $ ExitFailure i
                Continued -> waitForSyscall cpid
                Signaled s -> pure $ Right s
                Stopped s -> pure $ Right s

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
        Nothing -> putStrLn "Unknown Syscall."
        Just sc -> print sc

data Syscall
    = Exit
    | Fork
    | Read
    | Write
    | Open
    | Close
    | Execve
    | Prctl
    | ArchPrctl
    | Access
    | Poll
    | Openat
    | Fstat
    | Lstat
    | Nanosleep
    | Mmap
    | Lseek
    | Stat
    | Mprotect
    | Munmap
    | Brk
    | ExitGroup
    deriving (Show, Eq)

parseSyscall :: X86_64Regs -> Maybe Syscall
parseSyscall X86_64Regs {..} =
    case orig_rax of
        0 -> Just Read
        1 -> Just Write
        2 -> Just Open
        3 -> Just Close
        4 -> Just Stat
        5 -> Just Fstat
        6 -> Just Lstat
        7 -> Just Poll
        8 -> Just Lseek
        9 -> Just Mmap
        10 -> Just Mprotect
        11 -> Just Munmap
        12 -> Just Brk
        21 -> Just Access
        35 -> Just Nanosleep
        157 -> Just Prctl
        158 -> Just ArchPrctl
        231 -> Just ExitGroup
        257 -> Just Openat
        _ -> Nothing
