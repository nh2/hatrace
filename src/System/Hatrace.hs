{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

-- | Note about __safety of ptrace() in multi-threaded tracers__:
--
-- You must not call @ptrace(pid, ...)@ from an OS thread that's not the
-- tracer of @pid@. Otherwise you'll get an @ESRCH@ error (@No such process@).
--
-- So you must use `runInBoundThread` or @forkOS` around functions from this
-- module, unless their docs indicate that they already do this for you.
module System.Hatrace
  ( traceForkProcess
  , traceForkExecvFullPath
  , sourceRawTraceForkExecvFullPathWithSink
  , sourceTraceForkExecvFullPathWithSink
  , genericSourceTraceForkExecvFullPathWithSink
  , procToArgv
  , forkExecvWithPtrace
  , formatHatraceEventConduit
  , printHatraceEvent
  , printHatraceEventJson
  , SyscallEnterDetails_getcwd(..)
  , SyscallExitDetails_getcwd(..)
  , SyscallEnterDetails_open(..)
  , SyscallExitDetails_open(..)
  , SyscallEnterDetails_openat(..)
  , SyscallExitDetails_openat(..)
  , SyscallEnterDetails_creat(..)
  , SyscallExitDetails_creat(..)
  , SyscallEnterDetails_pipe(..)
  , SyscallExitDetails_pipe(..)
  , SyscallEnterDetails_pipe2(..)
  , SyscallExitDetails_pipe2(..)
  , SyscallEnterDetails_access(..)
  , SyscallExitDetails_access(..)
  , SyscallEnterDetails_faccessat(..)
  , SyscallExitDetails_faccessat(..)
  , SyscallEnterDetails_write(..)
  , SyscallExitDetails_write(..)
  , SyscallEnterDetails_read(..)
  , SyscallExitDetails_read(..)
  , SyscallEnterDetails_close(..)
  , SyscallExitDetails_close(..)
  , SyscallEnterDetails_rename(..)
  , SyscallExitDetails_rename(..)
  , SyscallEnterDetails_renameat(..)
  , SyscallExitDetails_renameat(..)
  , SyscallEnterDetails_renameat2(..)
  , SyscallExitDetails_renameat2(..)
  , SyscallEnterDetails_unlink(..)
  , SyscallExitDetails_unlink(..)
  , SyscallEnterDetails_unlinkat(..)
  , SyscallExitDetails_unlinkat(..)
  , SyscallEnterDetails_stat(..)
  , SyscallExitDetails_stat(..)
  , SyscallEnterDetails_fstat(..)
  , SyscallExitDetails_fstat(..)
  , SyscallEnterDetails_lstat(..)
  , SyscallExitDetails_lstat(..)
  , SyscallEnterDetails_newfstatat(..)
  , SyscallExitDetails_newfstatat(..)
  , SyscallEnterDetails_execve(..)
  , SyscallExitDetails_execve(..)
  , SyscallEnterDetails_exit(..)
  , SyscallExitDetails_exit(..)
  , SyscallEnterDetails_exit_group(..)
  , SyscallExitDetails_exit_group(..)
  , SyscallEnterDetails_socket(..)
  , SyscallExitDetails_socket(..)
  , SyscallEnterDetails_listen(..)
  , SyscallExitDetails_listen(..)
  , SyscallEnterDetails_shutdown(..)
  , SyscallExitDetails_shutdown(..)
  , SyscallEnterDetails_send(..)
  , SyscallExitDetails_send(..)
  , SyscallEnterDetails_sendto(..)
  , SyscallExitDetails_sendto(..)
  , SyscallEnterDetails_recv(..)
  , SyscallExitDetails_recv(..)
  , SyscallEnterDetails_recvfrom(..)
  , SyscallExitDetails_recvfrom(..)
  , SyscallEnterDetails_socketpair(..)
  , SyscallExitDetails_socketpair(..)
  , SyscallEnterDetails_mmap(..)
  , SyscallExitDetails_mmap(..)
  , SyscallEnterDetails_munmap(..)
  , SyscallExitDetails_munmap(..)
  , SyscallEnterDetails_madvise(..)
  , SyscallExitDetails_madvise(..)
  , SyscallEnterDetails_symlink(..)
  , SyscallExitDetails_symlink(..)
  , SyscallEnterDetails_symlinkat(..)
  , SyscallExitDetails_symlinkat(..)
  , SyscallEnterDetails_time(..)
  , SyscallExitDetails_time(..)
  , SyscallEnterDetails_brk(..)
  , SyscallExitDetails_brk(..)
  , SyscallEnterDetails_arch_prctl(..)
  , SyscallExitDetails_arch_prctl(..)
  , SyscallEnterDetails_set_tid_address(..)
  , SyscallExitDetails_set_tid_address(..)
  , SyscallEnterDetails_sysinfo(..)
  , SyscallExitDetails_sysinfo(..)
  , SyscallEnterDetails_poll(..)
  , SyscallExitDetails_poll(..)
  , SyscallEnterDetails_ppoll(..)
  , SyscallExitDetails_ppoll(..)
  , SyscallEnterDetails_mprotect(..)
  , SyscallExitDetails_mprotect(..)
  , SyscallEnterDetails_pkey_mprotect(..)
  , SyscallExitDetails_pkey_mprotect(..)
  , SyscallEnterDetails_sched_yield(..)
  , SyscallExitDetails_sched_yield(..)
  , SyscallEnterDetails_kill(..)
  , SyscallExitDetails_kill(..)
  , SyscallEnterDetails_clone(..)
  , SyscallExitDetails_clone(..)
  , DetailedSyscallEnter(..)
  , DetailedSyscallExit(..)
  , ERRNO(..)
  , foreignErrnoToERRNO
  , getSyscallEnterDetails
  , setExitedSyscallResult
  , syscallEnterDetailsOnlyConduit
  , syscallRawEnterDetailsOnlyConduit
  , syscallExitDetailsOnlyConduit
  , syscallRawExitDetailsOnlyConduit
  , FileWriteEvent(..)
  , fileWritesConduit
  , FileWriteBehavior(..)
  , atomicWritesSink
  , SyscallStopType(..)
  , TraceEvent(..)
  , TraceState(..)
  , Syscall(..)
  , SyscallArgs(..)
  , sendSignal
  , doesProcessHaveChildren
  , getFdPath
  , getExePath
  -- * Re-exports
  , KnownSyscall(..)
  ) where

import           Conduit (concatMapC, foldlC)
import           Control.Arrow (second)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.IO.Unlift (MonadUnliftIO)
import           Data.Aeson (ToJSON(..), (.=), encode, object)
import           Data.Bits ((.|.), shiftL, shiftR)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import qualified Data.ByteString.Internal as BSI
import qualified Data.ByteString.Lazy as BSL
import           Data.Conduit
import qualified Data.Conduit.List as CL
import           Data.Either (partitionEithers)
import           Data.List (genericLength)
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Word (Word32, Word64)
import           Foreign.C.Error (Errno(..), throwErrnoIfMinus1, throwErrnoIfMinus1_, getErrno, resetErrno, eCHILD, eINVAL)
import           Foreign.C.String (peekCString)
import           Foreign.C.Types (CInt(..), CUInt(..), CLong(..), CULong(..), CChar(..), CSize(..), CTime(..))
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Marshal.Alloc (alloca)
import           Foreign.Marshal.Array (withArray)
import qualified Foreign.Marshal.Array (peekArray)
import           Foreign.Marshal.Utils (withMany)
import           Foreign.Ptr (castPtr, Ptr, nullPtr, wordPtrToPtr)
import           Foreign.Storable (Storable, peekByteOff, sizeOf)
import           GHC.Stack (HasCallStack, callStack, getCallStack, prettySrcLoc)
import           System.Directory (canonicalizePath, doesFileExist, findExecutable)
import           System.Exit (ExitCode(..), die)
import           System.FilePath ((</>))
import           System.IO.Error (modifyIOError, ioeGetLocation, ioeSetLocation)
import           System.Linux.Ptrace (TracedProcess(..), peek, peekBytes, peekNullTerminatedBytes, peekNullWordTerminatedWords, detach)
import qualified System.Linux.Ptrace as Ptrace
import           System.Linux.Ptrace.Syscall hiding (ptrace_syscall, ptrace_detach)
import qualified System.Linux.Ptrace.Syscall as Ptrace.Syscall
import           System.Linux.Ptrace.Types (Regs(..))
import           System.Linux.Ptrace.X86_64Regs (X86_64Regs(..))
import           System.Linux.Ptrace.X86Regs (X86Regs(..))
import           System.Posix.Files (readSymbolicLink)
import           System.Posix.Internals (withFilePath)
import           System.Posix.Signals (Signal, sigTRAP, sigSTOP, sigTSTP, sigTTIN, sigTTOU)
import           System.Posix.Types (CPid(..), CMode(..))
import           System.Posix.Waitpid (waitpid, waitpidFullStatus, Status(..), FullStatus(..), Flag(..))
import           UnliftIO.Concurrent (runInBoundThread)
import           UnliftIO.IORef (newIORef, writeIORef, readIORef)

import           System.Hatrace.Format
import           System.Hatrace.Signals (signalMap)
import           System.Hatrace.SyscallTables.Generated (KnownSyscall(..), syscallMap_i386, syscallMap_x64_64)
import           System.Hatrace.Types


mapLeft :: (a1 -> a2) -> Either a1 b -> Either a2 b
mapLeft f = either (Left . f) Right


-- | Not using "Foreign.C.Error"'s `Errno` because it doesn't have a `Show`
-- instance, which would be a pain for consumers of our API.
--
-- Use `foreignErrnoToERRNO` to convert between them.
newtype ERRNO = ERRNO CInt
  deriving (Eq, Ord, Show)


-- | Turn a "Foreign.C.Error" `Errno` into `ERRNO`.
foreignErrnoToERRNO :: Errno -> ERRNO
foreignErrnoToERRNO (Errno e) = ERRNO e


-- | Adds some prefix (separated by @: @) to the error location of an `IOError`.
addIOErrorPrefix :: String -> IO a -> IO a
addIOErrorPrefix prefix action = do
  modifyIOError (\e -> ioeSetLocation e (prefix ++ ": " ++ ioeGetLocation e)) action


-- | We generally use this function to make it more obvious via what kind of
-- invocation of ptrace() it failed, because it's very easy to get
-- ptrace calls wrong. Without this, you'd just get
--
-- > ptrace: does not exist (No such process)
--
-- for pretty much any wrong invocation.
-- By adding the location to the exception, these
-- details show up in our test suite and our users' error messages.
--
-- Note that where possible, use a single invocation of this function
-- instead of nested invocations, so that the exception has to be caught
-- and rethrown as few times as possible.
annotatePtrace :: String -> IO a -> IO a
annotatePtrace = addIOErrorPrefix


-- | Wrapper around `Ptrace.System.ptrace_syscall` that prints its name in
-- `IOError`s it raises.
ptrace_syscall :: (HasCallStack) => CPid -> Maybe Signal -> IO ()
ptrace_syscall pid mbSignal = do
  let debugCallLocation = if
        | False -> -- set this to True to get caller source code lines for failures
            -- Put the top-most call stack caller into the error message
            concat
              [ prettySrcLoc srcLoc
              | (_, srcLoc):_ <- [getCallStack callStack]
              ] ++ " (pid " ++ show pid ++ "): "
        | otherwise -> ""
  annotatePtrace (debugCallLocation ++ "ptrace_syscall") $
    Ptrace.Syscall.ptrace_syscall pid mbSignal


-- | Wrapper around `Ptrace.System.detach` that prints its name in
-- `IOError`s it raises.
ptrace_detach :: CPid -> IO ()
ptrace_detach pid = annotatePtrace "ptrace_detach" $ detach (TracedProcess pid)


waitpidForExactPidStopOrError :: (HasCallStack) => CPid -> IO ()
waitpidForExactPidStopOrError pid = do
  mr <- waitpid pid []
  case mr of
    Nothing -> error "waitpidForExactPidStopOrError: BUG: no PID was returned by waitpid"
    Just (returnedPid, status)
      | returnedPid /= pid -> error $ "waitpidForExactPidStopOrError: BUG: returned PID != expected pid: " ++ show (returnedPid, pid)
      | otherwise ->
        case status of
          Stopped sig | sig == sigSTOP -> return () -- all OK
          -- TODO: This seems to happen when we ourselves (the tracer) are being `strace`d. Investigate.
          _ -> error $ "waitpidForExactPidStopOrError: BUG: unexpected status: " ++ show status


foreign import ccall safe "fork_exec_with_ptrace" c_fork_exec_with_ptrace :: CInt -> Ptr (Ptr CChar) -> IO CPid


-- | Forks a tracee process, makes it PTRACE_TRACEME and then SIGSTOP itself.
-- Waits for the tracee process to have entered the STOPPED state.
-- After waking up from the stop (as controlled by the tracer, that is,
-- other functions you'll use after calling this one),
-- the tracee will execv() the given program with arguments.
--
-- Since execv() is used, the first argument must be the /full path/
-- to the executable.
forkExecvWithPtrace :: (HasCallStack) => [String] -> IO CPid
forkExecvWithPtrace args = do
  childPid <- withMany withFilePath args $ \cstrs -> do
    withArray cstrs $ \argsPtr -> do
      let argc = genericLength args
      throwErrnoIfMinus1 "fork_exec_with_ptrace" $ c_fork_exec_with_ptrace argc argsPtr
  -- Wait for the tracee to stop itself
  waitpidForExactPidStopOrError childPid
  return childPid


-- | A conduit that starts a traced process from given @args@, and yields all
-- trace events that occur to it.
--
-- Already uses `runInBoundThread` internally, so using this ensures that you
-- don't accidentally run a @ptrace()@ call from an OS thread that's not the
-- tracer of the started process.
genericSourceTraceForkExecvFullPathWithSink ::
     (MonadUnliftIO m)
  => [String]
  -> (CPid -> IO details)
  -> ConduitT (CPid, TraceEvent details) Void m a
  -> m (ExitCode, a)
genericSourceTraceForkExecvFullPathWithSink args getDetails sink = runInBoundThread $ do
  childPid <- liftIO $ forkExecvWithPtrace args
  -- Now the child is stopped. Set options, then start it.
  liftIO $ annotatePtrace "ptrace_setoptions" $ ptrace_setoptions childPid
    -- Set `PTRACE_O_TRACESYSGOOD` to make it easy for the tracer
    -- to distinguish normal traps from those caused by a syscall.
    [ TraceSysGood
    -- Set `PTRACE_O_EXITKILL` so that if we crash, everything below
    -- also terminates.
    , ExitKill
    -- Tracing child processes
    , TraceClone
    , TraceFork
    , TraceVFork
    , TraceVForkDone
    -- Sign up for the various PTRACE_EVENT_* events we want to handle below.
    , TraceExec
    , TraceExit
    ]
  -- Start the child.
  liftIO $ ptrace_syscall childPid Nothing

  exitCodeRef <- newIORef (Nothing :: Maybe ExitCode)
  let loop state = do
        (newState, (returnedPid, event)) <- liftIO $ waitForTraceEvent state getDetails

        yield (returnedPid, event)

        -- Cases in which we have to restart the tracee
        -- (by calling `ptrace_syscall` again).
        liftIO $ case event of
          SyscallStop _enterOrExit _details -> do
            -- Tell the process to continue into / out of the syscall,
            -- and generate another event at the next syscall or signal.
            ptrace_syscall returnedPid Nothing
          PTRACE_EVENT_Stop _ptraceEvent -> do
            -- Continue past the event.
            ptrace_syscall returnedPid Nothing
            -- As discussed in the docs of PTRACE_EVENT_EXIT, even for that
            -- event the child is still alive and needs to be restarted
            -- before it truly exits.
          GroupStop sig -> do
            -- Continue past the event.
            ptrace_syscall returnedPid (Just sig)
          SignalDeliveryStop sig -> do
            -- Deliver the signal
            ptrace_syscall returnedPid (Just sig)
          Death _exitCode -> return () -- can't restart it, it's dead

        -- The program runs.
        -- It is in this section of the code where the traced program actually runs:
        -- between `ptrace_syscall` and `waitForTraceEvent`'s waitpid()' returning
        -- (this statement is of course only accurate for single-threaded programs
        -- without child processes; otherwise multiple things can be running).

        case event of
          Death exitCode | returnedPid == childPid -> do
            -- Our direct child exited, we are done.
            -- TODO: Figure out how to handle the situation that our
            --       direct child exits when children are still alive
            --       (because it didn't reap them or because they
            --       double-forked to daemonize).
            writeIORef exitCodeRef (Just exitCode)
            -- no further `loop`ing
          _ -> do
            loop newState

  a <- runConduit $ loop initialTraceState .| sink
  mExitCode <- readIORef exitCodeRef
  finalExitCode <- liftIO $ case mExitCode of
    Just e -> pure e
    Nothing -> do
      -- If the child hasn't exited yet, Detach from it and let it run
      -- to an end.
      -- TODO: We probably have to do that for all tracees.
      preDetachWaitpidResult <- waitpid childPid []
      case preDetachWaitpidResult of
        Nothing -> error "genericSourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
        Just{} -> do
          -- TODO as the man page says:
          --        PTRACE_DETACH  is a restarting operation; therefore it requires the tracee to be in ptrace-stop.
          --      We need to ensure/check we're in a ptrace-stop here.
          --      Further from the man page:
          --        If the tracee is running when the tracer wants to detach it, the usual
          --        solution is to send SIGSTOP (using tgkill(2), to make sure it goes to
          --        the correct  thread),  wait  for the  tracee  to  stop  in
          --        signal-delivery-stop for SIGSTOP and then detach it (suppressing
          --        SIGSTOP injection).  A design bug is that this can race with concurrent
          --        SIGSTOPs. Another complication is that the tracee may enter other
          --        ptrace-stops and needs to be restarted and waited for again, until
          --        SIGSTOP is seen.  Yet another complication  is  to be sure that the
          --        tracee is not already ptrace-stopped, because no signal delivery
          --        happens while it is—not even SIGSTOP.
          ptrace_detach childPid
          waitpidResult <- waitpidFullStatus childPid []
          case waitpidResult of
            Nothing -> error "genericSourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
            Just (_returnedPid, status, FullStatus fullStatus) -> case status of
              Exited 0 -> pure ExitSuccess
              _ -> pure $ ExitFailure (fromIntegral fullStatus)
  return (finalExitCode, a)

sourceTraceForkExecvFullPathWithSink ::
     (MonadUnliftIO m)
  => [String]
  -> ConduitT (CPid, TraceEvent EnterDetails) Void m a
  -> m (ExitCode, a)
sourceTraceForkExecvFullPathWithSink args sink =
  genericSourceTraceForkExecvFullPathWithSink args getEnterDetails sink

sourceRawTraceForkExecvFullPathWithSink ::
     (MonadUnliftIO m)
  => [String]
  -> ConduitT (CPid, TraceEvent (Syscall, SyscallArgs)) Void m a
  -> m (ExitCode, a)
sourceRawTraceForkExecvFullPathWithSink args sink =
  genericSourceTraceForkExecvFullPathWithSink args getEnteredSyscall sink

wordToPtr :: Word -> Ptr a
wordToPtr w = wordPtrToPtr (fromIntegral w)
{-# INLINE wordToPtr #-}


word64ToPtr :: Word64 -> Ptr a
word64ToPtr w = wordPtrToPtr (fromIntegral w)
{-# INLINE word64ToPtr #-}


-- * Syscall details
--
-- __Note:__ The data types below use @DuplicateRecordFields@.
--
-- Users should also use @DuplicateRecordFields@ to avoid getting
-- @Ambiguous occurrence@ errors.

data SyscallEnterDetails_getcwd = SyscallEnterDetails_getcwd
  { buf :: Ptr CChar
  , size :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_getcwd where
  syscallEnterToFormatted SyscallEnterDetails_getcwd{ size } =
    FormattedSyscall "getcwd" [argPlaceholder "*buf", formatArg size]


data SyscallExitDetails_getcwd = SyscallExitDetails_getcwd
  { enterDetail :: SyscallEnterDetails_getcwd
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_getcwd where
  syscallExitToFormatted SyscallExitDetails_getcwd{ enterDetail, bufContents } =
    ( FormattedSyscall "getcwd" [formatArg bufContents, formatArg size]
    , formatReturn bufContents
    )
    where
      SyscallEnterDetails_getcwd{ size } = enterDetail


data SyscallEnterDetails_open = SyscallEnterDetails_open
  { pathname :: Ptr CChar
  , flags :: CInt
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_open where
  syscallEnterToFormatted SyscallEnterDetails_open{ pathnameBS, flags, mode } =
    FormattedSyscall "open" [formatArg pathnameBS, formatArg flags, formatArg mode]


data SyscallExitDetails_open = SyscallExitDetails_open
  { enterDetail :: SyscallEnterDetails_open
  , fd :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_open where
  syscallExitToFormatted SyscallExitDetails_open{ enterDetail, fd } =
    (syscallEnterToFormatted enterDetail, formatReturn fd)


data SyscallEnterDetails_openat = SyscallEnterDetails_openat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , flags :: CInt
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_openat where
  syscallEnterToFormatted SyscallEnterDetails_openat{ dirfd, pathnameBS, flags, mode } =
    FormattedSyscall "openat" [ formatArg dirfd, formatArg pathnameBS
                              , formatArg flags, formatArg mode
                              ]


data SyscallExitDetails_openat = SyscallExitDetails_openat
  { enterDetail :: SyscallEnterDetails_openat
  , fd :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_openat where
  syscallExitToFormatted SyscallExitDetails_openat{ enterDetail, fd } =
    (syscallEnterToFormatted enterDetail, formatReturn fd)


data SyscallEnterDetails_creat = SyscallEnterDetails_creat
  { pathname :: Ptr CChar
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_creat where
  syscallEnterToFormatted SyscallEnterDetails_creat{ pathnameBS, mode } =
    FormattedSyscall "creat" [formatArg pathnameBS, formatArg mode]


data SyscallExitDetails_creat = SyscallExitDetails_creat
  { enterDetail :: SyscallEnterDetails_creat
  , fd :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_creat where
  syscallExitToFormatted SyscallExitDetails_creat{ enterDetail, fd } =
    (syscallEnterToFormatted enterDetail, formatReturn fd)


data SyscallEnterDetails_pipe = SyscallEnterDetails_pipe
  { pipefd :: Ptr CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_pipe where
  syscallEnterToFormatted  SyscallEnterDetails_pipe{ } = FormattedSyscall "pipe" []


data SyscallExitDetails_pipe = SyscallExitDetails_pipe
  { enterDetail :: SyscallEnterDetails_pipe
  , readfd :: CInt
  , writefd :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_pipe where
  syscallExitToFormatted SyscallExitDetails_pipe{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_pipe2 = SyscallEnterDetails_pipe2
  { pipefd :: Ptr CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_pipe2 where
  syscallEnterToFormatted  SyscallEnterDetails_pipe2{ } = FormattedSyscall "pipe2" []


data SyscallExitDetails_pipe2 = SyscallExitDetails_pipe2
  { enterDetail :: SyscallEnterDetails_pipe2
  , readfd :: CInt
  , writefd :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_pipe2 where
  syscallExitToFormatted SyscallExitDetails_pipe2{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_exit = SyscallEnterDetails_exit
  { status :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_exit where
  syscallEnterToFormatted SyscallEnterDetails_exit{ status } =
    FormattedSyscall "exit"  [formatArg status]


data SyscallExitDetails_exit = SyscallExitDetails_exit
  { enterDetail :: SyscallEnterDetails_exit
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_exit where
  syscallExitToFormatted SyscallExitDetails_exit{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_exit_group = SyscallEnterDetails_exit_group
  { status :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_exit_group where
  syscallEnterToFormatted SyscallEnterDetails_exit_group{ status } =
    FormattedSyscall "exit_group" [formatArg status]


data SyscallExitDetails_exit_group = SyscallExitDetails_exit_group
  { enterDetail :: SyscallEnterDetails_exit_group
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_exit_group where
  syscallExitToFormatted SyscallExitDetails_exit_group{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_write = SyscallEnterDetails_write
  { fd :: CInt
  , buf :: Ptr Void
  , count :: CSize
  -- Peeked details
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_write where
  syscallEnterToFormatted SyscallEnterDetails_write{ fd, bufContents, count } =
    FormattedSyscall "write" [formatArg fd, formatArg bufContents, formatArg count]


data SyscallExitDetails_write = SyscallExitDetails_write
  { enterDetail :: SyscallEnterDetails_write
  , writtenCount :: CSize
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_write where
  syscallExitToFormatted SyscallExitDetails_write{ enterDetail, writtenCount } =
    (syscallEnterToFormatted enterDetail, formatReturn writtenCount)


data SyscallEnterDetails_read = SyscallEnterDetails_read
  { fd :: CInt
  , buf :: Ptr Void
  , count :: CSize
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_read where
  syscallEnterToFormatted SyscallEnterDetails_read{ fd, count } =
    FormattedSyscall "read" [formatArg fd, argPlaceholder "*buf", formatArg count]


data SyscallExitDetails_read = SyscallExitDetails_read
  { enterDetail :: SyscallEnterDetails_read
  -- Peeked details
  , readCount :: CSize
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_read where
  syscallExitToFormatted SyscallExitDetails_read{ enterDetail, bufContents, readCount } =
    ( FormattedSyscall "read" [formatArg fd, formatArg bufContents, formatArg count]
    , formatReturn readCount
    )
    where
      SyscallEnterDetails_read{ fd, count } = enterDetail


data SyscallEnterDetails_close = SyscallEnterDetails_close
  { fd :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_close where
  syscallEnterToFormatted SyscallEnterDetails_close{ fd } =
    FormattedSyscall "close" [formatArg fd]


data SyscallExitDetails_close = SyscallExitDetails_close
  { enterDetail :: SyscallEnterDetails_close
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_close where
  syscallExitToFormatted SyscallExitDetails_close{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_rename = SyscallEnterDetails_rename
  { oldpath :: Ptr CChar
  , newpath :: Ptr CChar
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_rename where
  syscallEnterToFormatted SyscallEnterDetails_rename{ oldpathBS, newpathBS } =
    FormattedSyscall "rename" [formatArg oldpathBS, formatArg newpathBS]


data SyscallExitDetails_rename = SyscallExitDetails_rename
  { enterDetail :: SyscallEnterDetails_rename
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_rename where
  syscallExitToFormatted SyscallExitDetails_rename{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_renameat = SyscallEnterDetails_renameat
  { olddirfd :: CInt
  , oldpath :: Ptr CChar
  , newdirfd :: CInt
  , newpath :: Ptr CChar
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_renameat where
  syscallEnterToFormatted SyscallEnterDetails_renameat{ olddirfd, oldpathBS, newdirfd, newpathBS } =
    FormattedSyscall "renameat" [ formatArg olddirfd, formatArg oldpathBS
                                , formatArg newdirfd, formatArg newpathBS
                                ]


data SyscallExitDetails_renameat = SyscallExitDetails_renameat
  { enterDetail :: SyscallEnterDetails_renameat
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_renameat where
  syscallExitToFormatted SyscallExitDetails_renameat{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_renameat2 = SyscallEnterDetails_renameat2
  { olddirfd :: CInt
  , oldpath :: Ptr CChar
  , newdirfd :: CInt
  , newpath :: Ptr CChar
  , flags :: CInt
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_renameat2 where
  syscallEnterToFormatted SyscallEnterDetails_renameat2{ olddirfd, oldpathBS, newdirfd, newpathBS, flags } =
    FormattedSyscall "renameat2" [ formatArg olddirfd, formatArg oldpathBS
                                 , formatArg newdirfd, formatArg newpathBS
                                 , formatArg flags
                                 ]


data SyscallExitDetails_renameat2 = SyscallExitDetails_renameat2
  { enterDetail :: SyscallEnterDetails_renameat2
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_renameat2 where
  syscallExitToFormatted SyscallExitDetails_renameat2{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_unlink = SyscallEnterDetails_unlink
  { pathname :: Ptr CChar
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_unlink where
  syscallEnterToFormatted SyscallEnterDetails_unlink{ pathnameBS } =
    FormattedSyscall "unlink" [formatArg pathnameBS]


data SyscallExitDetails_unlink = SyscallExitDetails_unlink
  { enterDetail :: SyscallEnterDetails_unlink
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_unlink where
  syscallExitToFormatted SyscallExitDetails_unlink{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_unlinkat = SyscallEnterDetails_unlinkat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , flags :: CInt
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_unlinkat where
  syscallEnterToFormatted SyscallEnterDetails_unlinkat{ dirfd, pathnameBS, flags } =
    FormattedSyscall "unlinkat" [formatArg dirfd, formatArg pathnameBS, formatArg flags]


data SyscallExitDetails_unlinkat = SyscallExitDetails_unlinkat
  { enterDetail :: SyscallEnterDetails_unlinkat
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_unlinkat where
  syscallExitToFormatted SyscallExitDetails_unlinkat{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_access = SyscallEnterDetails_access
  { pathname :: Ptr CChar
  , mode :: CInt
  -- Peeked details
  , accessMode :: FileAccessMode
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_access where
  syscallEnterToFormatted SyscallEnterDetails_access{ pathnameBS, accessMode } =
    FormattedSyscall "access" [formatArg pathnameBS, formatArg accessMode]


data SyscallExitDetails_access = SyscallExitDetails_access
  { enterDetail :: SyscallEnterDetails_access
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_access where
  syscallExitToFormatted SyscallExitDetails_access{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_faccessat = SyscallEnterDetails_faccessat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , mode :: CInt
  , flags :: CInt
  -- Peeked details
  , accessMode :: FileAccessMode
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_faccessat where
  syscallEnterToFormatted SyscallEnterDetails_faccessat{ dirfd, pathnameBS, accessMode, flags } =
    FormattedSyscall "faccessat" [ formatArg dirfd, formatArg pathnameBS
                                 , formatArg accessMode, formatArg flags
                                 ]


data SyscallExitDetails_faccessat = SyscallExitDetails_faccessat
  { enterDetail :: SyscallEnterDetails_faccessat
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_faccessat where
  syscallExitToFormatted SyscallExitDetails_faccessat{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_stat = SyscallEnterDetails_stat
  { pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_stat where
  syscallEnterToFormatted SyscallEnterDetails_stat{ pathnameBS } =
    FormattedSyscall "stat" [formatArg pathnameBS, argPlaceholder "*statbuf"]


data SyscallExitDetails_stat = SyscallExitDetails_stat
  { enterDetail :: SyscallEnterDetails_stat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_stat where
  syscallExitToFormatted SyscallExitDetails_stat { enterDetail, stat } =
    ( FormattedSyscall "stat" [formatArg pathnameBS, formatArg stat]
    , NoReturn
    )
    where
      SyscallEnterDetails_stat{ pathnameBS } = enterDetail


data SyscallEnterDetails_fstat = SyscallEnterDetails_fstat
  { fd :: CInt
  , statbuf :: Ptr StatStruct
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_fstat where
  syscallEnterToFormatted SyscallEnterDetails_fstat{ fd } =
    FormattedSyscall "fstat" [formatArg fd, argPlaceholder "*statbuf"]


data SyscallExitDetails_fstat = SyscallExitDetails_fstat
  { enterDetail :: SyscallEnterDetails_fstat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_fstat where
  syscallExitToFormatted SyscallExitDetails_fstat{ enterDetail, stat } =
    ( FormattedSyscall "fstat" [formatArg fd, formatArg stat]
    , NoReturn
    )
    where
      SyscallEnterDetails_fstat{ fd } = enterDetail


data SyscallEnterDetails_lstat = SyscallEnterDetails_lstat
  { pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_lstat where
  syscallEnterToFormatted SyscallEnterDetails_lstat{ pathnameBS } =
    FormattedSyscall "lstat" [formatArg pathnameBS, argPlaceholder "*statbuf"]


data SyscallExitDetails_lstat = SyscallExitDetails_lstat
  { enterDetail :: SyscallEnterDetails_lstat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_lstat where
  syscallExitToFormatted SyscallExitDetails_lstat{ enterDetail, stat } =
    ( FormattedSyscall "lstat" [formatArg pathnameBS, formatArg stat]
    , NoReturn
    )
    where
      SyscallEnterDetails_lstat{ pathnameBS } = enterDetail


data SyscallEnterDetails_newfstatat = SyscallEnterDetails_newfstatat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  , flags :: CInt
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_newfstatat where
  syscallEnterToFormatted SyscallEnterDetails_newfstatat{ dirfd, pathnameBS, flags } =
    FormattedSyscall "newfstatat" [ formatArg dirfd, formatArg pathnameBS
                                  , argPlaceholder "*statbuf", formatArg flags
                                  ]


data SyscallExitDetails_newfstatat = SyscallExitDetails_newfstatat
  { enterDetail :: SyscallEnterDetails_newfstatat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_newfstatat where
  syscallExitToFormatted SyscallExitDetails_newfstatat{ enterDetail, stat } =
    ( FormattedSyscall "newfstatat" [ formatArg dirfd, formatArg pathnameBS
                                    , formatArg stat, formatArg flags
                                    ]
    , NoReturn
    )
    where
      SyscallEnterDetails_newfstatat{ dirfd, pathnameBS, flags } = enterDetail


data SyscallEnterDetails_execve = SyscallEnterDetails_execve
  { filename :: Ptr CChar
  , argv :: Ptr (Ptr CChar)
  , envp :: Ptr (Ptr CChar)
  -- Peeked details
  , filenameBS :: ByteString
  , argvList :: [ByteString]
  , envpList :: [ByteString]
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_execve where
  syscallEnterToFormatted SyscallEnterDetails_execve{ filenameBS, argvList, envpList } =
    FormattedSyscall "execve" [formatArg filenameBS, formatArg argvList, formatArg envpList]


data SyscallExitDetails_execve = SyscallExitDetails_execve
  { optionalEnterDetail :: Maybe SyscallEnterDetails_execve
  , execveResult :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_execve where
  syscallExitToFormatted SyscallExitDetails_execve { optionalEnterDetail, execveResult } =
    (FormattedSyscall "execve" args, formatReturn execveResult)
    where
      args = case optionalEnterDetail of
        Just SyscallEnterDetails_execve{ filenameBS, argvList, envpList } ->
          [formatArg filenameBS, formatArg argvList, formatArg envpList]
        Nothing ->
          [argPlaceholder "getRawSyscallExitDetails was used thus no enter details could be found"]

data SyscallEnterDetails_symlink = SyscallEnterDetails_symlink
  { target :: Ptr CChar
  , linkpath :: Ptr CChar
  -- Peeked details
  , targetBS :: ByteString
  , linkpathBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_symlink where
  syscallEnterToFormatted SyscallEnterDetails_symlink{ targetBS, linkpathBS } =
    FormattedSyscall "symlink" [formatArg targetBS, formatArg linkpathBS]

data SyscallExitDetails_symlink = SyscallExitDetails_symlink
  { enterDetail :: SyscallEnterDetails_symlink
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_symlink where
  syscallExitToFormatted SyscallExitDetails_symlink { enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_symlinkat = SyscallEnterDetails_symlinkat
  { dirfd :: CInt
  , target :: Ptr CChar
  , linkpath :: Ptr CChar
  -- Peeked details
  , targetBS :: ByteString
  , linkpathBS :: ByteString
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_symlinkat where
  syscallEnterToFormatted SyscallEnterDetails_symlinkat{ targetBS, dirfd, linkpathBS } =
    FormattedSyscall "symlinkat" [formatArg targetBS, formatArg dirfd, formatArg linkpathBS]


data SyscallExitDetails_symlinkat = SyscallExitDetails_symlinkat
  { enterDetail :: SyscallEnterDetails_symlinkat
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_symlinkat where
  syscallExitToFormatted SyscallExitDetails_symlinkat { enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_time = SyscallEnterDetails_time
  { tloc :: Ptr CTime
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_time where
  syscallEnterToFormatted SyscallEnterDetails_time{ tloc } =
    FormattedSyscall "time" [formatPtrArg "time_t" tloc]


data SyscallExitDetails_time = SyscallExitDetails_time
  { enterDetail :: SyscallEnterDetails_time
  -- Peeked details
  , timeResult :: CTime
  } deriving (Eq, Ord, Show)

-- TODO: add formatted time output (like strace does), along with a pointer
instance SyscallExitFormatting SyscallExitDetails_time where
  syscallExitToFormatted SyscallExitDetails_time { enterDetail, timeResult } =
    (syscallEnterToFormatted enterDetail, formatReturn timeResult)


data SyscallEnterDetails_brk = SyscallEnterDetails_brk
  { addr :: Ptr Void
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_brk where
  syscallEnterToFormatted SyscallEnterDetails_brk{ addr } =
    FormattedSyscall "brk" [formatArg addr]


data SyscallExitDetails_brk = SyscallExitDetails_brk
  { enterDetail :: SyscallEnterDetails_brk
  -- | From Linux Programmer's Manual:
  -- On success, brk() returns zero. On error, -1 is returned, and errno
  -- is set to ENOMEM. [...] However, the actual Linux system call returns the
  -- new program break on success. On failure, the system call returns
  -- the current break. The glibc wrapper function does some work (i.e.,
  -- checks whether the new break is less than addr) to provide the 0 and
  -- -1 return values described above.
  , brkResult :: Ptr Void
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_brk where
  syscallExitToFormatted SyscallExitDetails_brk{ enterDetail, brkResult } =
    (syscallEnterToFormatted enterDetail, formatReturn brkResult)

data SyscallEnterDetails_poll = SyscallEnterDetails_poll
  { fds :: Ptr PollFdStruct
  , nfds :: CULong
  , timeout :: CInt
  , fdsValue :: [PollFdStruct]
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_poll where
  syscallEnterToFormatted SyscallEnterDetails_poll{ fdsValue, nfds, timeout} =
    FormattedSyscall "poll" [formatArg fdsValue, formatArg nfds, formatArg timeout]

data SyscallExitDetails_poll = SyscallExitDetails_poll
  { enterDetail :: SyscallEnterDetails_poll
  , fdsValue :: [PollFdStruct]
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_poll where
  syscallExitToFormatted SyscallExitDetails_poll{ enterDetail, fdsValue } =
    (syscallEnterToFormatted enterDetail, formatReturn fdsValue)

data SyscallEnterDetails_ppoll = SyscallEnterDetails_ppoll
  { fds :: Ptr PollFdStruct
  , nfds :: CULong
  , tmo_p :: Ptr TimespecStruct
  , sigmask :: Ptr SigSet
  , fdsValue :: [PollFdStruct]
  , tmo_pValue :: TimespecStruct
  , sigmaskValue :: SigSet
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_ppoll where
  syscallEnterToFormatted SyscallEnterDetails_ppoll{ fdsValue, nfds, tmo_pValue, sigmaskValue } =
    FormattedSyscall "ppoll" [ formatArg fdsValue, formatArg nfds
                             , formatArg tmo_pValue, formatArg sigmaskValue]

data SyscallExitDetails_ppoll = SyscallExitDetails_ppoll
  { enterDetail :: SyscallEnterDetails_ppoll
  , fdsValue :: [PollFdStruct]
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_ppoll where
  syscallExitToFormatted SyscallExitDetails_ppoll{ enterDetail, fdsValue } =
    ( syscallEnterToFormatted enterDetail
    , FormattedReturn $ formatArg fdsValue
    )

data ArchPrctlAddrArg
  = ArchPrctlAddrArgVal CULong
  | ArchPrctlAddrArgPtr (Ptr CULong)
  | ArchPrctlAddrArgUnknown CULong
  deriving (Eq, Ord, Show)

instance ArgFormatting ArchPrctlAddrArg where
  formatArg (ArchPrctlAddrArgVal val) = formatArg val
  formatArg (ArchPrctlAddrArgPtr ptr) = formatPtrArg "unsigned long" ptr
  formatArg (ArchPrctlAddrArgUnknown val) = formatArg val

data SyscallEnterDetails_arch_prctl = SyscallEnterDetails_arch_prctl
  { code :: CInt
  , addr :: ArchPrctlAddrArg
  -- Peeked details
  , subfunction :: ArchPrctlSubfunction
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_arch_prctl where
  syscallEnterToFormatted SyscallEnterDetails_arch_prctl{ subfunction, addr } =
    FormattedSyscall "arch_prctl" [formatArg subfunction, formatArg addr]


data SyscallExitDetails_arch_prctl = SyscallExitDetails_arch_prctl
  { enterDetail :: SyscallEnterDetails_arch_prctl
  -- Peeked details
  , addrValue :: CULong
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_arch_prctl where
  syscallExitToFormatted SyscallExitDetails_arch_prctl{ enterDetail, addrValue } =
    ( FormattedSyscall "arch_prctl" [formatArg subfunction, formatArg addrValue]
    , NoReturn)
    where
      SyscallEnterDetails_arch_prctl{ subfunction } = enterDetail

data SyscallEnterDetails_set_tid_address = SyscallEnterDetails_set_tid_address
  { tidptr :: Ptr CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_set_tid_address where
  syscallEnterToFormatted SyscallEnterDetails_set_tid_address{ tidptr } =
    FormattedSyscall "set_tid_address" [formatPtrArg "int" tidptr]


data SyscallExitDetails_set_tid_address = SyscallExitDetails_set_tid_address
  { enterDetail :: SyscallEnterDetails_set_tid_address
  -- Peeked details
  , tidResult :: CLong
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_set_tid_address where
  syscallExitToFormatted SyscallExitDetails_set_tid_address{ enterDetail, tidResult } =
    ( syscallEnterToFormatted enterDetail, formatReturn tidResult )


data SyscallEnterDetails_sysinfo = SyscallEnterDetails_sysinfo
  { info :: Ptr SysinfoStruct
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_sysinfo where
  syscallEnterToFormatted SyscallEnterDetails_sysinfo{ info } =
    FormattedSyscall "sysinfo" [formatPtrArg "sysinfo" info]


data SyscallExitDetails_sysinfo = SyscallExitDetails_sysinfo
  { enterDetail :: SyscallEnterDetails_sysinfo
  , sysinfo :: SysinfoStruct
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_sysinfo where
  syscallExitToFormatted SyscallExitDetails_sysinfo{ sysinfo } =
    (FormattedSyscall "sysinfo" [formatArg sysinfo], NoReturn)


data SyscallEnterDetails_mprotect = SyscallEnterDetails_mprotect
  { addr :: Ptr Void
  , len :: CSize
  , prot :: CInt
  -- Peeked details
  , protection :: AccessProtection
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_mprotect where
  syscallEnterToFormatted SyscallEnterDetails_mprotect{ addr, len, prot } =
    FormattedSyscall "mprotect" [formatArg addr, formatArg len, formatArg prot]


data SyscallExitDetails_mprotect = SyscallExitDetails_mprotect
  { enterDetail :: SyscallEnterDetails_mprotect
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_mprotect where
  syscallExitToFormatted SyscallExitDetails_mprotect{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_pkey_mprotect = SyscallEnterDetails_pkey_mprotect
  { addr :: Ptr Void
  , len :: CSize
  , prot :: CInt
  , pkey :: CInt
  -- Peeked details
  , protection :: AccessProtection
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_pkey_mprotect where
  syscallEnterToFormatted SyscallEnterDetails_pkey_mprotect{ addr, len, prot } =
    FormattedSyscall "pkey_mprotect" [formatArg addr, formatArg len, formatArg prot]


data SyscallExitDetails_pkey_mprotect = SyscallExitDetails_pkey_mprotect
  { enterDetail :: SyscallEnterDetails_pkey_mprotect
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_pkey_mprotect where
  syscallExitToFormatted SyscallExitDetails_pkey_mprotect{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_mmap = SyscallEnterDetails_mmap
  { addr :: Ptr Void
  , len :: CSize
  , prot :: MemoryProtectMode
  , flags :: MMapMode
  , fd :: CInt
  , offset :: CSize
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_mmap where
  syscallEnterToFormatted SyscallEnterDetails_mmap{ addr, len, prot, flags, fd, offset } =
    FormattedSyscall "mmap" [ formatArg addr, formatArg len, formatArg prot
                            , formatArg flags, formatArg fd, formatArg offset
                            ]


data SyscallExitDetails_mmap = SyscallExitDetails_mmap
  { enterDetail :: SyscallEnterDetails_mmap
  , mappedArea :: Ptr Void
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_mmap where
  syscallExitToFormatted SyscallExitDetails_mmap{ enterDetail, mappedArea } =
    ( syscallEnterToFormatted enterDetail
    , formatReturn mappedArea)


data SyscallEnterDetails_munmap = SyscallEnterDetails_munmap
  { addr :: Ptr Void
  , len :: CSize
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_munmap where
  syscallEnterToFormatted SyscallEnterDetails_munmap{ addr, len } =
    FormattedSyscall "munmap" [ formatArg addr, formatArg len ]


data SyscallExitDetails_munmap = SyscallExitDetails_munmap
  { enterDetail :: SyscallEnterDetails_munmap
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_munmap where
  syscallExitToFormatted SyscallExitDetails_munmap{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_madvise = SyscallEnterDetails_madvise
  { addr :: Ptr Void
  , length_ :: CSize
  , advice :: CInt
  -- Peeked details
  , memAdvice :: MemAdvice
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_madvise where
  syscallEnterToFormatted SyscallEnterDetails_madvise{ addr, length_, memAdvice } =
    FormattedSyscall "madvise" [ formatArg addr, formatArg length_, formatArg memAdvice ]


data SyscallExitDetails_madvise = SyscallExitDetails_madvise
  { enterDetail :: SyscallEnterDetails_madvise
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_madvise where
  syscallExitToFormatted SyscallExitDetails_madvise{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_socket = SyscallEnterDetails_socket
  { domain :: CInt
  , type_ :: CInt
  , protocol :: CInt
  -- Peeked details
  , addressFamily :: AddressFamily
  , socketType :: SocketType
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_socket where
  syscallEnterToFormatted SyscallEnterDetails_socket{ addressFamily, socketType, protocol } =
    FormattedSyscall "socket" [ formatArg addressFamily, formatArg socketType, formatArg protocol ]


data SyscallExitDetails_socket = SyscallExitDetails_socket
  { enterDetail :: SyscallEnterDetails_socket
  , fd :: CInt
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_socket where
  syscallExitToFormatted SyscallExitDetails_socket{ enterDetail, fd } =
    ( syscallEnterToFormatted enterDetail
    , formatReturn fd)


data SyscallEnterDetails_listen = SyscallEnterDetails_listen
  { fd :: CInt
  , backlog :: CInt
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_listen where
  syscallEnterToFormatted SyscallEnterDetails_listen{ fd, backlog } =
    FormattedSyscall "listen" [ formatArg fd, formatArg backlog ]


data SyscallExitDetails_listen = SyscallExitDetails_listen
  { enterDetail :: SyscallEnterDetails_listen
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_listen where
  syscallExitToFormatted SyscallExitDetails_listen{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_shutdown = SyscallEnterDetails_shutdown
  { fd :: CInt
  , how :: CInt
  -- Peeked details
  , shutdownHow :: ShutdownHow
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_shutdown where
  syscallEnterToFormatted SyscallEnterDetails_shutdown{ fd, shutdownHow } =
    FormattedSyscall "shutdown" [ formatArg fd, formatArg shutdownHow ]


data SyscallExitDetails_shutdown = SyscallExitDetails_shutdown
  { enterDetail :: SyscallEnterDetails_shutdown
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_shutdown where
  syscallExitToFormatted SyscallExitDetails_shutdown{ enterDetail } =
    (syscallEnterToFormatted enterDetail, NoReturn)


data SyscallEnterDetails_send = SyscallEnterDetails_send
  { fd :: CInt
  , buf :: Ptr Void
  , len :: CSize
  , flags :: CUInt
  -- Peeked details
  , bufContents :: ByteString
  , msgFlags :: SendFlags
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_send where
  syscallEnterToFormatted SyscallEnterDetails_send{ fd, bufContents, len, msgFlags } =
    FormattedSyscall "send" [ formatArg fd, formatArg bufContents, formatArg len, formatArg msgFlags ]


data SyscallExitDetails_send = SyscallExitDetails_send
  { enterDetail :: SyscallEnterDetails_send
  , numSent :: CInt
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_send where
  syscallExitToFormatted SyscallExitDetails_send{ enterDetail, numSent } =
    (syscallEnterToFormatted enterDetail, formatReturn numSent)


data SyscallEnterDetails_sendto = SyscallEnterDetails_sendto
  { fd :: CInt
  , buf :: Ptr Void
  , len :: CSize
  , flags :: CUInt
  , addr :: Ptr Void -- TODO StructSockAddr
  , addrlen :: CInt
  -- Peeked details
  , bufContents :: ByteString
  , msgFlags :: SendFlags
  } deriving (Eq, Ord, Show)


-- TODO sockaddr
instance SyscallEnterFormatting SyscallEnterDetails_sendto where
  syscallEnterToFormatted SyscallEnterDetails_sendto{ fd, bufContents, len, flags, addr, addrlen } =
    FormattedSyscall "sendto" [ formatArg fd, formatArg bufContents, formatArg len
                              , formatArg flags, formatArg addr, formatArg addrlen
                              ]


data SyscallExitDetails_sendto = SyscallExitDetails_sendto
  { enterDetail :: SyscallEnterDetails_sendto
  , numSent :: CInt
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_sendto where
  syscallExitToFormatted SyscallExitDetails_sendto{ enterDetail, numSent } =
    (syscallEnterToFormatted enterDetail, formatReturn numSent)


data SyscallEnterDetails_recv = SyscallEnterDetails_recv
  { fd :: CInt
  , buf :: Ptr Void
  , size :: CSize
  , flags :: CUInt
  -- Peeked details
  , msgFlags :: ReceiveFlags
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_recv where
  syscallEnterToFormatted SyscallEnterDetails_recv{ fd, buf, size, flags } =
    FormattedSyscall "recv" [ formatArg fd, formatArg buf, formatArg size, formatArg flags ]


data SyscallExitDetails_recv = SyscallExitDetails_recv
  { enterDetail :: SyscallEnterDetails_recv
  , numReceived :: CInt
  -- Peeked details
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_recv where
  syscallExitToFormatted SyscallExitDetails_recv{ enterDetail, numReceived, bufContents } =
    ( FormattedSyscall "recv" [ formatArg fd, formatArg bufContents, formatArg size, formatArg msgFlags ]
    , formatReturn numReceived)
    where
      SyscallEnterDetails_recv{ fd, size, msgFlags } = enterDetail


data SyscallEnterDetails_recvfrom = SyscallEnterDetails_recvfrom
  { fd :: CInt
  , buf :: Ptr Void
  , size :: CSize
  , flags :: CUInt
  , addr :: Ptr Void -- TODO StructSockAddr
  , addrlen :: Ptr CInt
  -- Peeked details
  , msgFlags :: ReceiveFlags
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_recvfrom where
  syscallEnterToFormatted SyscallEnterDetails_recvfrom{ fd, buf, size, flags, addr, addrlen } =
    FormattedSyscall "recvfrom" [ formatArg fd, formatArg buf, formatArg size
                                , formatArg flags, formatArg addr, formatPtrArg "int" addrlen ]


data SyscallExitDetails_recvfrom = SyscallExitDetails_recvfrom
  { enterDetail :: SyscallEnterDetails_recvfrom
  , numReceived :: CInt
  -- Peeked details
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_recvfrom where
  syscallExitToFormatted SyscallExitDetails_recvfrom{ enterDetail, numReceived, bufContents } =
    ( FormattedSyscall "recvfrom" [ formatArg fd, formatArg bufContents, formatArg size
                                  , formatArg msgFlags, formatArg addr, formatPtrArg "int" addrlen
                                  ]
    , formatReturn numReceived)
    where
      SyscallEnterDetails_recvfrom{ fd, size, msgFlags, addr, addrlen } = enterDetail


data SyscallEnterDetails_socketpair = SyscallEnterDetails_socketpair
  { domain :: CInt
  , type_ :: CInt
  , protocol :: CInt
  -- | points to an array of 2 CInts i.e. 'int sv[2]' in C headers
  , sv :: Ptr CInt
  -- Peeked details
  , addressFamily :: AddressFamily
  , socketType :: SocketType
  } deriving (Eq, Ord, Show)


instance SyscallEnterFormatting SyscallEnterDetails_socketpair where
  syscallEnterToFormatted SyscallEnterDetails_socketpair{ addressFamily, socketType, protocol, sv } =
    FormattedSyscall "socketpair" [ formatArg addressFamily, formatArg socketType
                                  , formatArg protocol, formatPtrArg "int" sv ]


data SyscallExitDetails_socketpair = SyscallExitDetails_socketpair
  { enterDetail :: SyscallEnterDetails_socketpair
  -- Peeked details
  , sockfd1 :: CInt
  , sockfd2 :: CInt
  } deriving (Eq, Ord, Show)


instance SyscallExitFormatting SyscallExitDetails_socketpair where
  syscallExitToFormatted SyscallExitDetails_socketpair{ enterDetail, sockfd1, sockfd2 } =
    ( FormattedSyscall "socketpair" [ formatArg addressFamily, formatArg socketType
                                    , formatArg protocol, formatArg [sockfd1, sockfd2]
                                    ]
    , NoReturn)
    where
      SyscallEnterDetails_socketpair{ addressFamily, socketType, protocol } = enterDetail

data SyscallEnterDetails_kill = SyscallEnterDetails_kill
  { pid :: CPid
  , sig :: CInt
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_kill where
  syscallEnterToFormatted SyscallEnterDetails_kill{ pid, sig } =
    let signalString = case snd <$> Map.lookup sig signalMap of
          Just s  -> "SIG" <> s
          Nothing -> show sig
    in FormattedSyscall "kill" [ formatArg pid, FixedStringArg signalString]

data SyscallExitDetails_kill = SyscallExitDetails_kill
  { enterDetail :: SyscallEnterDetails_kill
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_kill where
  syscallExitToFormatted SyscallExitDetails_kill{ enterDetail } =
    ( syscallEnterToFormatted enterDetail, NoReturn )

data SyscallEnterDetails_sched_yield = SyscallEnterDetails_sched_yield
  deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_sched_yield where
  syscallEnterToFormatted SyscallEnterDetails_sched_yield =
    FormattedSyscall "sched_yield" []


data SyscallExitDetails_sched_yield = SyscallExitDetails_sched_yield
  deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_sched_yield where
  syscallExitToFormatted SyscallExitDetails_sched_yield =
    (syscallEnterToFormatted SyscallEnterDetails_sched_yield, NoReturn)

-- | We're using the order of arguments of glibc wrapper like strace does
data SyscallEnterDetails_clone = SyscallEnterDetails_clone
  { child_stack :: Ptr Void
  , flags :: CULong
  , ptid :: Ptr CInt
  , newtls :: CULong
  , ctid :: Ptr CInt
  -- Peeked details
  , termSignal :: Signal
  -- ^ The low byte of flags contains the number of the termination signal
  -- sent to the parent when the child dies. See clone(2) for more details.
  , cloneFlags :: CloneFlags
  } deriving (Eq, Ord, Show)

instance SyscallEnterFormatting SyscallEnterDetails_clone where
  syscallEnterToFormatted SyscallEnterDetails_clone{ child_stack, ptid, newtls, ctid, termSignal, cloneFlags } =
    FormattedSyscall "clone" [ formatArg child_stack, formatCloneFlagsArg termSignal cloneFlags
                             , formatPtrArg "int" ptid, formatArg newtls, formatPtrArg "int" ctid]


data SyscallExitDetails_clone = SyscallExitDetails_clone
  { enterDetail :: SyscallEnterDetails_clone
  -- Peeked details
  , childPid :: CPid
  } deriving (Eq, Ord, Show)

instance SyscallExitFormatting SyscallExitDetails_clone where
  syscallExitToFormatted SyscallExitDetails_clone{ enterDetail, childPid } =
    (syscallEnterToFormatted enterDetail, formatReturn childPid)


data DetailedSyscallEnter
  = DetailedSyscallEnter_getcwd SyscallEnterDetails_getcwd
  | DetailedSyscallEnter_open SyscallEnterDetails_open
  | DetailedSyscallEnter_openat SyscallEnterDetails_openat
  | DetailedSyscallEnter_creat SyscallEnterDetails_creat
  | DetailedSyscallEnter_pipe SyscallEnterDetails_pipe
  | DetailedSyscallEnter_pipe2 SyscallEnterDetails_pipe2
  | DetailedSyscallEnter_access SyscallEnterDetails_access
  | DetailedSyscallEnter_faccessat SyscallEnterDetails_faccessat
  | DetailedSyscallEnter_write SyscallEnterDetails_write
  | DetailedSyscallEnter_read SyscallEnterDetails_read
  | DetailedSyscallEnter_execve SyscallEnterDetails_execve
  | DetailedSyscallEnter_close SyscallEnterDetails_close
  | DetailedSyscallEnter_rename SyscallEnterDetails_rename
  | DetailedSyscallEnter_renameat SyscallEnterDetails_renameat
  | DetailedSyscallEnter_renameat2 SyscallEnterDetails_renameat2
  | DetailedSyscallEnter_unlink SyscallEnterDetails_unlink
  | DetailedSyscallEnter_unlinkat SyscallEnterDetails_unlinkat
  | DetailedSyscallEnter_stat SyscallEnterDetails_stat
  | DetailedSyscallEnter_fstat SyscallEnterDetails_fstat
  | DetailedSyscallEnter_lstat SyscallEnterDetails_lstat
  | DetailedSyscallEnter_newfstatat SyscallEnterDetails_newfstatat
  | DetailedSyscallEnter_exit SyscallEnterDetails_exit
  | DetailedSyscallEnter_exit_group SyscallEnterDetails_exit_group
  | DetailedSyscallEnter_socket SyscallEnterDetails_socket
  | DetailedSyscallEnter_listen SyscallEnterDetails_listen
  | DetailedSyscallEnter_shutdown SyscallEnterDetails_shutdown
  | DetailedSyscallEnter_send SyscallEnterDetails_send
  | DetailedSyscallEnter_sendto SyscallEnterDetails_sendto
  | DetailedSyscallEnter_recv SyscallEnterDetails_recv
  | DetailedSyscallEnter_recvfrom SyscallEnterDetails_recvfrom
  | DetailedSyscallEnter_socketpair SyscallEnterDetails_socketpair
  | DetailedSyscallEnter_mmap SyscallEnterDetails_mmap
  | DetailedSyscallEnter_munmap SyscallEnterDetails_munmap
  | DetailedSyscallEnter_madvise SyscallEnterDetails_madvise
  | DetailedSyscallEnter_symlink SyscallEnterDetails_symlink
  | DetailedSyscallEnter_symlinkat SyscallEnterDetails_symlinkat
  | DetailedSyscallEnter_time SyscallEnterDetails_time
  | DetailedSyscallEnter_brk SyscallEnterDetails_brk
  | DetailedSyscallEnter_arch_prctl SyscallEnterDetails_arch_prctl
  | DetailedSyscallEnter_set_tid_address SyscallEnterDetails_set_tid_address
  | DetailedSyscallEnter_sysinfo SyscallEnterDetails_sysinfo
  | DetailedSyscallEnter_poll SyscallEnterDetails_poll
  | DetailedSyscallEnter_ppoll SyscallEnterDetails_ppoll
  | DetailedSyscallEnter_mprotect SyscallEnterDetails_mprotect
  | DetailedSyscallEnter_pkey_mprotect SyscallEnterDetails_pkey_mprotect
  | DetailedSyscallEnter_sched_yield SyscallEnterDetails_sched_yield
  | DetailedSyscallEnter_kill SyscallEnterDetails_kill
  | DetailedSyscallEnter_clone SyscallEnterDetails_clone
  | DetailedSyscallEnter_unimplemented Syscall SyscallArgs
  deriving (Eq, Ord, Show)


data DetailedSyscallExit
  = DetailedSyscallExit_getcwd SyscallExitDetails_getcwd
  | DetailedSyscallExit_open SyscallExitDetails_open
  | DetailedSyscallExit_openat SyscallExitDetails_openat
  | DetailedSyscallExit_creat SyscallExitDetails_creat
  | DetailedSyscallExit_pipe SyscallExitDetails_pipe
  | DetailedSyscallExit_pipe2 SyscallExitDetails_pipe2
  | DetailedSyscallExit_access SyscallExitDetails_access
  | DetailedSyscallExit_faccessat SyscallExitDetails_faccessat
  | DetailedSyscallExit_write SyscallExitDetails_write
  | DetailedSyscallExit_read SyscallExitDetails_read
  | DetailedSyscallExit_execve SyscallExitDetails_execve
  | DetailedSyscallExit_close SyscallExitDetails_close
  | DetailedSyscallExit_rename SyscallExitDetails_rename
  | DetailedSyscallExit_renameat SyscallExitDetails_renameat
  | DetailedSyscallExit_renameat2 SyscallExitDetails_renameat2
  | DetailedSyscallExit_unlink SyscallExitDetails_unlink
  | DetailedSyscallExit_unlinkat SyscallExitDetails_unlinkat
  | DetailedSyscallExit_stat SyscallExitDetails_stat
  | DetailedSyscallExit_fstat SyscallExitDetails_fstat
  | DetailedSyscallExit_lstat SyscallExitDetails_lstat
  | DetailedSyscallExit_newfstatat SyscallExitDetails_newfstatat
  | DetailedSyscallExit_exit SyscallExitDetails_exit
  | DetailedSyscallExit_exit_group SyscallExitDetails_exit_group
  | DetailedSyscallExit_socket SyscallExitDetails_socket
  | DetailedSyscallExit_listen SyscallExitDetails_listen
  | DetailedSyscallExit_shutdown SyscallExitDetails_shutdown
  | DetailedSyscallExit_send SyscallExitDetails_send
  | DetailedSyscallExit_sendto SyscallExitDetails_sendto
  | DetailedSyscallExit_recv SyscallExitDetails_recv
  | DetailedSyscallExit_recvfrom SyscallExitDetails_recvfrom
  | DetailedSyscallExit_socketpair SyscallExitDetails_socketpair
  | DetailedSyscallExit_mmap SyscallExitDetails_mmap
  | DetailedSyscallExit_munmap SyscallExitDetails_munmap
  | DetailedSyscallExit_madvise SyscallExitDetails_madvise
  | DetailedSyscallExit_symlink SyscallExitDetails_symlink
  | DetailedSyscallExit_symlinkat SyscallExitDetails_symlinkat
  | DetailedSyscallExit_time SyscallExitDetails_time
  | DetailedSyscallExit_brk SyscallExitDetails_brk
  | DetailedSyscallExit_arch_prctl SyscallExitDetails_arch_prctl
  | DetailedSyscallExit_set_tid_address SyscallExitDetails_set_tid_address
  | DetailedSyscallExit_sysinfo SyscallExitDetails_sysinfo
  | DetailedSyscallExit_poll SyscallExitDetails_poll
  | DetailedSyscallExit_ppoll SyscallExitDetails_ppoll
  | DetailedSyscallExit_mprotect SyscallExitDetails_mprotect
  | DetailedSyscallExit_pkey_mprotect SyscallExitDetails_pkey_mprotect
  | DetailedSyscallExit_sched_yield SyscallExitDetails_sched_yield
  | DetailedSyscallExit_kill SyscallExitDetails_kill
  | DetailedSyscallExit_clone SyscallExitDetails_clone
  | DetailedSyscallExit_unimplemented Syscall SyscallArgs Word64
  deriving (Eq, Ord, Show)

data EnterDetails
  = KnownEnterDetails !KnownSyscall DetailedSyscallEnter
  | UnknownEnterDetails !Word64 !SyscallArgs
  deriving (Eq, Ord, Show)

enterDetailsToSyscall :: EnterDetails -> Syscall
enterDetailsToSyscall details = case details of
  KnownEnterDetails known _ -> KnownSyscall known
  UnknownEnterDetails unknown _ -> UnknownSyscall unknown

data ExitDetails
  = KnownExitDetails !KnownSyscall DetailedSyscallExit
  | UnknownExitDetails !Word64 !SyscallArgs
  deriving (Eq, Ord, Show)

exitDetailsToSyscall :: ExitDetails -> Syscall
exitDetailsToSyscall details = case details of
  KnownExitDetails known _ -> KnownSyscall known
  UnknownExitDetails unknown _ -> UnknownSyscall unknown

getEnterDetails :: CPid -> IO EnterDetails
getEnterDetails pid = do
  (syscall, syscallArgs) <- getEnteredSyscall pid
  case syscall of
    KnownSyscall knownSyscall ->
      KnownEnterDetails knownSyscall <$> getSyscallEnterDetails knownSyscall syscallArgs pid
    UnknownSyscall unknown ->
      pure $ UnknownEnterDetails unknown syscallArgs

getSyscallEnterDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO DetailedSyscallEnter
getSyscallEnterDetails syscall syscallArgs pid = let proc = TracedProcess pid in case syscall of
  Syscall_getcwd -> do
    let SyscallArgs{ arg0 = buf, arg1 = size } = syscallArgs
    pure $ DetailedSyscallEnter_getcwd $ SyscallEnterDetails_getcwd
      { buf = word64ToPtr buf
      , size = fromIntegral size
      }
  Syscall_open -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = flags, arg2 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_open $ SyscallEnterDetails_open
      { pathname = pathnamePtr
      , flags = fromIntegral flags
      , mode = fromIntegral mode
      , pathnameBS
      }
  Syscall_openat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathnameAddr, arg2 = flags, arg3 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_openat $ SyscallEnterDetails_openat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , flags = fromIntegral flags
      , mode = fromIntegral mode
      , pathnameBS
      }
  Syscall_creat -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_creat $ SyscallEnterDetails_creat
      { pathname = pathnamePtr
      , mode = fromIntegral mode
      , pathnameBS
      }
  Syscall_pipe -> do
    let SyscallArgs{ arg0 = pipefdAddr } = syscallArgs
    let pipefdPtr = word64ToPtr pipefdAddr
    pure $ DetailedSyscallEnter_pipe $ SyscallEnterDetails_pipe
      { pipefd = pipefdPtr
      }
  Syscall_pipe2 -> do
    let SyscallArgs{ arg0 = pipefdAddr, arg1 = flags } = syscallArgs
    let pipefdPtr = word64ToPtr pipefdAddr
    pure $ DetailedSyscallEnter_pipe2 $ SyscallEnterDetails_pipe2
      { pipefd = pipefdPtr
      , flags = fromIntegral flags
      }
  Syscall_access -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = mode } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_access $ SyscallEnterDetails_access
      { pathname = pathnamePtr
      , mode = fromIntegral mode
      , accessMode = fromCInt (fromIntegral mode)
      , pathnameBS
      }
  Syscall_faccessat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathnameAddr, arg2 = mode, arg3 = flags } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_faccessat $ SyscallEnterDetails_faccessat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , mode = fromIntegral mode
      , accessMode = fromCInt (fromIntegral mode)
      , pathnameBS
      , flags = fromIntegral flags
      }
  Syscall_write -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufContents <- peekBytes proc bufPtr (fromIntegral count)
    pure $ DetailedSyscallEnter_write $ SyscallEnterDetails_write
      { fd = fromIntegral fd
      , buf = bufPtr
      , count = fromIntegral count
      , bufContents
      }
  Syscall_read -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_read $ SyscallEnterDetails_read
      { fd = fromIntegral fd
      , buf = bufPtr
      , count = fromIntegral count
      }
  Syscall_execve -> do
    let SyscallArgs{ arg0 = filenameAddr, arg1 = argvPtrsAddr, arg2 = envpPtrsAddr } = syscallArgs
    let filenamePtr = word64ToPtr filenameAddr
    let argvPtrsPtr = word64ToPtr argvPtrsAddr
    let envpPtrsPtr = word64ToPtr envpPtrsAddr
    filenameBS <- peekNullTerminatedBytes proc filenamePtr
    -- Per `man 2 execve`:
    --     On Linux, argv and envp can be specified as NULL.
    --     In both cases, this has the same effect as specifying the argument
    --     as a pointer to a list containing a single null pointer.
    --     Do not take advantage of this nonstandard and nonportable misfeature!
    --     On many other UNIX systems, specifying argv as NULL will result in
    --     an error (EFAULT).
    --     Some other UNIX systems treat the envp==NULL case the same as Linux.
    -- We handle the case that `argv` or `envp` are NULL below.

    argvPtrs <-
      if argvPtrsPtr == nullPtr
        then pure []
        else peekNullWordTerminatedWords proc argvPtrsPtr
    envpPtrs <-
      if envpPtrsPtr == nullPtr
        then pure []
        else peekNullWordTerminatedWords proc envpPtrsPtr

    argvList <- mapM (peekNullTerminatedBytes proc . wordToPtr) argvPtrs
    envpList <- mapM (peekNullTerminatedBytes proc . wordToPtr) envpPtrs

    pure $ DetailedSyscallEnter_execve $ SyscallEnterDetails_execve
      { filename = filenamePtr
      , argv = argvPtrsPtr
      , envp = envpPtrsPtr
      , filenameBS
      , argvList
      , envpList
      }
  Syscall_close -> do
    let SyscallArgs{ arg0 = fd } = syscallArgs
    pure $ DetailedSyscallEnter_close $ SyscallEnterDetails_close
      { fd = fromIntegral fd
      }
  Syscall_rename -> do
    let SyscallArgs{ arg0 = oldpathAddr, arg1 = newpathAddr } = syscallArgs
    let oldpathPtr = word64ToPtr oldpathAddr
    let newpathPtr = word64ToPtr newpathAddr
    oldpathBS <- peekNullTerminatedBytes proc oldpathPtr
    newpathBS <- peekNullTerminatedBytes proc newpathPtr
    pure $ DetailedSyscallEnter_rename $ SyscallEnterDetails_rename
      { oldpath = oldpathPtr
      , newpath = newpathPtr
      , oldpathBS
      , newpathBS
      }
  Syscall_renameat -> do
    let SyscallArgs{ arg0 = olddirfd, arg1 = oldpathAddr, arg2 =newdirfd, arg3 = newpathAddr } = syscallArgs
    let oldpathPtr = word64ToPtr oldpathAddr
    let newpathPtr = word64ToPtr newpathAddr
    oldpathBS <- peekNullTerminatedBytes proc oldpathPtr
    newpathBS <- peekNullTerminatedBytes proc newpathPtr
    pure $ DetailedSyscallEnter_renameat $ SyscallEnterDetails_renameat
      { olddirfd = fromIntegral olddirfd
      , oldpath = oldpathPtr
      , newdirfd = fromIntegral newdirfd
      , newpath = newpathPtr
      , oldpathBS
      , newpathBS
      }
  Syscall_renameat2 -> do
    let SyscallArgs{ arg0 = olddirfd, arg1 = oldpathAddr
                   , arg2 = newdirfd, arg3 = newpathAddr, arg4 = flags } = syscallArgs
    let oldpathPtr = word64ToPtr oldpathAddr
    let newpathPtr = word64ToPtr newpathAddr
    oldpathBS <- peekNullTerminatedBytes proc oldpathPtr
    newpathBS <- peekNullTerminatedBytes proc newpathPtr
    pure $ DetailedSyscallEnter_renameat2 $ SyscallEnterDetails_renameat2
      { olddirfd = fromIntegral olddirfd
      , oldpath = oldpathPtr
      , newdirfd = fromIntegral newdirfd
      , newpath = newpathPtr
      , oldpathBS
      , newpathBS
      , flags = fromIntegral flags
      }
  Syscall_unlink -> do
    let SyscallArgs{ arg0 = pathname } = syscallArgs
        pathnamePtr = word64ToPtr pathname
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_unlink $ SyscallEnterDetails_unlink
      { pathname = pathnamePtr
      , pathnameBS
      }
  Syscall_unlinkat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathname, arg2 = flags } = syscallArgs
        pathnamePtr = word64ToPtr pathname
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_unlinkat $ SyscallEnterDetails_unlinkat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , flags = fromIntegral flags
      , pathnameBS
      }
  Syscall_stat -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = statbufAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let statbufPtr = word64ToPtr statbufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_stat $ SyscallEnterDetails_stat
      { pathname = pathnamePtr
      , statbuf = statbufPtr
      , pathnameBS
      }
  Syscall_fstat -> do
    let SyscallArgs{ arg0 = fd, arg1 = statbufAddr } = syscallArgs
    let statbufPtr = word64ToPtr statbufAddr
    pure $ DetailedSyscallEnter_fstat $ SyscallEnterDetails_fstat
      { fd = fromIntegral fd
      , statbuf = statbufPtr
      }
  Syscall_lstat -> do
    let SyscallArgs{ arg0 = pathnameAddr, arg1 = statbufAddr } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let statbufPtr = word64ToPtr statbufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_lstat $ SyscallEnterDetails_lstat
      { pathname = pathnamePtr
      , statbuf = statbufPtr
      , pathnameBS
      }
  Syscall_newfstatat -> do
    let SyscallArgs{ arg0 = dirfd, arg1 = pathnameAddr, arg2 = statbufAddr, arg3 = flags } = syscallArgs
    let pathnamePtr = word64ToPtr pathnameAddr
    let statbufPtr = word64ToPtr statbufAddr
    pathnameBS <- peekNullTerminatedBytes proc pathnamePtr
    pure $ DetailedSyscallEnter_newfstatat $ SyscallEnterDetails_newfstatat
      { dirfd = fromIntegral dirfd
      , pathname = pathnamePtr
      , statbuf = statbufPtr
      , flags = fromIntegral flags
      , pathnameBS
      }
  Syscall_exit -> do
    let SyscallArgs{ arg0 = status } = syscallArgs
    pure $ DetailedSyscallEnter_exit $ SyscallEnterDetails_exit { status = fromIntegral status }
  Syscall_exit_group -> do
    let SyscallArgs{ arg0 = status } = syscallArgs
    pure $ DetailedSyscallEnter_exit_group $ SyscallEnterDetails_exit_group { status = fromIntegral status }
  Syscall_socket -> do
    let SyscallArgs{ arg0 = domain, arg1 = type_, arg2 = protocol } = syscallArgs
    pure $ DetailedSyscallEnter_socket $ SyscallEnterDetails_socket
      { domain = fromIntegral domain
      , type_ = fromIntegral type_
      , protocol = fromIntegral protocol
      , addressFamily = fromCInt (fromIntegral domain)
      , socketType = fromCInt (fromIntegral type_)
      }
  Syscall_listen -> do
    let SyscallArgs{ arg0 = fd, arg1 = backlog } = syscallArgs
    pure $ DetailedSyscallEnter_listen $ SyscallEnterDetails_listen
      { fd = fromIntegral fd
      , backlog = fromIntegral backlog
      }
  Syscall_shutdown -> do
    let SyscallArgs{ arg0 = fd, arg1 = how } = syscallArgs
    pure $ DetailedSyscallEnter_shutdown $ SyscallEnterDetails_shutdown
      { fd = fromIntegral fd
      , how = fromIntegral how
      , shutdownHow = fromCInt (fromIntegral how)
      }
  Syscall_send -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = len, arg3 = flags } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    bufContents <- peekBytes proc bufPtr (fromIntegral len)
    pure $ DetailedSyscallEnter_send $ SyscallEnterDetails_send
      { fd = fromIntegral fd
      , buf = bufPtr
      , len = fromIntegral len
      , flags = fromIntegral flags
      , bufContents
      , msgFlags = fromCInt (fromIntegral flags)
      }
  Syscall_mmap -> do
    let SyscallArgs{ arg0 = addr, arg1 = len, arg2 = prot, arg3 = flags, arg4 = fd, arg5 = offset } = syscallArgs
    let addrPtr = word64ToPtr addr
    pure $ DetailedSyscallEnter_mmap $ SyscallEnterDetails_mmap
      { addr = addrPtr
      , len = fromIntegral len
      , prot = fromCInt $ fromIntegral prot
      , flags = fromCInt $ fromIntegral flags
      , fd = fromIntegral fd
      , offset = fromIntegral offset
      }
  Syscall_sendto -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = len, arg3 = flags, arg4 = addrAddr, arg5 = addrlen } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    let addrPtr = word64ToPtr addrAddr
    bufContents <- peekBytes proc bufPtr (fromIntegral len)
    pure $ DetailedSyscallEnter_sendto $ SyscallEnterDetails_sendto
      { fd = fromIntegral fd
      , buf = bufPtr
      , len = fromIntegral len
      , flags = fromIntegral flags
      , addr = addrPtr
      , addrlen = fromIntegral addrlen
      , bufContents
      , msgFlags = fromCInt (fromIntegral flags)
      }
  Syscall_recv -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = size, arg3 = flags } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    pure $ DetailedSyscallEnter_recv $ SyscallEnterDetails_recv
      { fd = fromIntegral fd
      , buf = bufPtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      , msgFlags = fromCInt (fromIntegral flags)
      }
  Syscall_recvfrom -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = size, arg3 = flags, arg4 = addrAddr, arg5 = addrlenAddr } = syscallArgs
    let bufPtr = word64ToPtr bufAddr
    let addrPtr = word64ToPtr addrAddr
    let addrlenPtr = word64ToPtr addrlenAddr
    pure $ DetailedSyscallEnter_recvfrom $ SyscallEnterDetails_recvfrom
      { fd = fromIntegral fd
      , buf = bufPtr
      , size = fromIntegral size
      , flags = fromIntegral flags
      , addr = addrPtr
      , addrlen = addrlenPtr
      , msgFlags = fromCInt (fromIntegral flags)
      }
  Syscall_socketpair -> do
    let SyscallArgs{ arg0 = domain, arg1 = type_, arg2 = protocol, arg3 = svAddr } = syscallArgs
    let svPtr = word64ToPtr svAddr
    pure $ DetailedSyscallEnter_socketpair $ SyscallEnterDetails_socketpair
      { domain = fromIntegral domain
      , type_ = fromIntegral type_
      , protocol = fromIntegral protocol
      , sv = svPtr
      , addressFamily = fromCInt (fromIntegral domain)
      , socketType = fromCInt (fromIntegral type_)
      }
  Syscall_munmap -> do
    let SyscallArgs{ arg0 = addr, arg1 = len } = syscallArgs
    let addrPtr = word64ToPtr addr
    pure $ DetailedSyscallEnter_munmap $ SyscallEnterDetails_munmap
      { addr = addrPtr
      , len = fromIntegral len
      }
  Syscall_madvise -> do
    let SyscallArgs{ arg0 = addrAddr, arg1 = length_, arg2 = advice } = syscallArgs
    let addrPtr = word64ToPtr addrAddr
    pure $ DetailedSyscallEnter_madvise $ SyscallEnterDetails_madvise
      { addr = addrPtr
      , length_ = fromIntegral length_
      , advice = fromIntegral advice
      , memAdvice = fromCInt (fromIntegral advice)
      }
  Syscall_symlink -> do
    let SyscallArgs{ arg0 = targetAddr, arg1 = linkpathAddr } = syscallArgs
    let targetPtr = word64ToPtr targetAddr
    let linkpathPtr = word64ToPtr linkpathAddr
    targetBS <- peekNullTerminatedBytes proc targetPtr
    linkpathBS <- peekNullTerminatedBytes proc linkpathPtr
    pure $ DetailedSyscallEnter_symlink $ SyscallEnterDetails_symlink
      { target = targetPtr
      , linkpath = linkpathPtr
      , targetBS
      , linkpathBS
      }
  Syscall_symlinkat -> do
    let SyscallArgs{ arg0 = targetAddr, arg1 = fddir, arg2 = linkpathAddr } = syscallArgs
    let targetPtr = word64ToPtr targetAddr
    let linkpathPtr = word64ToPtr linkpathAddr
    targetBS <- peekNullTerminatedBytes proc targetPtr
    linkpathBS <- peekNullTerminatedBytes proc linkpathPtr
    pure $ DetailedSyscallEnter_symlinkat $ SyscallEnterDetails_symlinkat
      { target = targetPtr
      , dirfd = fromIntegral fddir
      , linkpath = linkpathPtr
      , targetBS
      , linkpathBS
      }
  Syscall_time -> do
    let SyscallArgs{ arg0 = tlocAddr } = syscallArgs
    let tlocPtr = word64ToPtr tlocAddr
    pure $ DetailedSyscallEnter_time $ SyscallEnterDetails_time
      { tloc = tlocPtr
      }
  Syscall_brk -> do
    let SyscallArgs{ arg0 = addr } = syscallArgs
    let addrPtr = word64ToPtr addr
    pure $ DetailedSyscallEnter_brk $ SyscallEnterDetails_brk { addr = addrPtr }
  Syscall_arch_prctl -> do
    let SyscallArgs{ arg0 = codeWord, arg1 = addrUnion } = syscallArgs
    let code = fromIntegral codeWord
    let subfunction = fromCInt (fromIntegral code)
    let addrArg =
          if
            | subfunction == ArchSetFs || subfunction == ArchSetGs ->
              ArchPrctlAddrArgVal $ fromIntegral addrUnion
            | subfunction == ArchGetFs || subfunction == ArchGetGs ->
              ArchPrctlAddrArgPtr $ word64ToPtr addrUnion
            | otherwise ->
              ArchPrctlAddrArgUnknown $ fromIntegral addrUnion
    pure $ DetailedSyscallEnter_arch_prctl $ SyscallEnterDetails_arch_prctl
      { code
      , addr = addrArg
      , subfunction
      }
  Syscall_sysinfo -> do
    let SyscallArgs{ arg0 = infoAddr } = syscallArgs
    let infoPtr = word64ToPtr infoAddr
    pure $ DetailedSyscallEnter_sysinfo $ SyscallEnterDetails_sysinfo { info = infoPtr }
  Syscall_set_tid_address -> do
    let SyscallArgs{ arg0 = pidAddr } = syscallArgs
    let tidptr = word64ToPtr pidAddr
    pure $ DetailedSyscallEnter_set_tid_address $ SyscallEnterDetails_set_tid_address
      { tidptr
      }
  Syscall_poll -> do
    let SyscallArgs{ arg0 = fdsAddr, arg1 = nfds, arg2 = timeout } = syscallArgs
        fdsPtr = word64ToPtr fdsAddr
        -- This capping to max int below is a consequence of nfds var being a long,
        -- while peekArray taking as an argument just an int. The assumption made
        -- in here is that the number of checked fds will be less than max int.
        n = fromIntegral $ min nfds $ fromIntegral (maxBound :: Int)
    fdsValue <- peekArray (TracedProcess pid) n fdsPtr
    pure $ DetailedSyscallEnter_poll $ SyscallEnterDetails_poll
      { fds = fdsPtr
      , nfds = fromIntegral nfds
      , timeout = fromIntegral timeout
      , fdsValue
      }
  Syscall_ppoll -> do
    let SyscallArgs{ arg0 = fdsAddr, arg1 = nfds
                   , arg2 = tmopAddr, arg3 = sigmaskAddr } = syscallArgs
        fdsPtr = word64ToPtr fdsAddr
        tmopPtr = word64ToPtr tmopAddr
        sigmaskPtr = word64ToPtr sigmaskAddr
        -- This capping to max int below is a consequence of nfds var being a long,
        -- while peekArray taking as an argument just an int. The assumption made
        -- in here is that the number of checked fds will be less than max int.
        n = fromIntegral $ min nfds $ fromIntegral (maxBound :: Int)
    fdsValue <- peekArray (TracedProcess pid) n fdsPtr
    tmo_pValue <- peek (TracedProcess pid) tmopPtr
    sigmaskValue <- peek (TracedProcess pid) sigmaskPtr
    pure $ DetailedSyscallEnter_ppoll $ SyscallEnterDetails_ppoll
      { fds = fdsPtr
      , nfds = fromIntegral nfds
      , tmo_p = tmopPtr
      , sigmask = sigmaskPtr
      , fdsValue
      , tmo_pValue
      , sigmaskValue
      }
  Syscall_mprotect -> do
    let SyscallArgs{ arg0 = addr, arg1 = len, arg2 = protWord } = syscallArgs
    let addrPtr = word64ToPtr addr
    let prot = fromIntegral protWord
    pure $ DetailedSyscallEnter_mprotect $ SyscallEnterDetails_mprotect
      { addr = addrPtr
      , len = fromIntegral len
      , prot = prot
      , protection = fromCInt prot
      }
  Syscall_pkey_mprotect -> do
    let SyscallArgs{ arg0 = addr, arg1 = len, arg2 = protWord, arg3 = pkey } = syscallArgs
    let addrPtr = word64ToPtr addr
    let prot = fromIntegral protWord
    pure $ DetailedSyscallEnter_pkey_mprotect $ SyscallEnterDetails_pkey_mprotect
      { addr = addrPtr
      , len = fromIntegral len
      , prot = prot
      , pkey = fromIntegral pkey
      , protection = fromCInt prot
      }
  Syscall_sched_yield -> do
    pure $ DetailedSyscallEnter_sched_yield SyscallEnterDetails_sched_yield
  Syscall_kill -> do
    let SyscallArgs{ arg0 = cpid, arg1 = signal } = syscallArgs
    pure $ DetailedSyscallEnter_kill $ SyscallEnterDetails_kill
      { pid = fromIntegral cpid
      , sig = fromIntegral signal
      }
  Syscall_clone -> do
    -- order of arguments for x86-64, x86-32 has ctid and newtls swapped
    let SyscallArgs{ arg0 = flags, arg1 = child_stack
                   , arg2 = ptid, arg3 = ctid, arg4 = newtls } = syscallArgs
    let child_stackAddr = word64ToPtr child_stack
    let ptidAddr = word64ToPtr ptid
    let ctidAddr = word64ToPtr ctid
    let (termSignal, cloneFlags) = fromCloneFlagsArg (fromIntegral flags)
    pure $ DetailedSyscallEnter_clone $ SyscallEnterDetails_clone
      { flags = fromIntegral flags
      , child_stack = child_stackAddr
      , ptid = ptidAddr
      , ctid = ctidAddr
      , newtls = fromIntegral newtls
      , termSignal = termSignal
      , cloneFlags = cloneFlags
      }
  _ -> pure $ DetailedSyscallEnter_unimplemented (KnownSyscall syscall) syscallArgs

getRawSyscallExitDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO (Either ERRNO DetailedSyscallExit)
getRawSyscallExitDetails knownSyscall syscallArgs pid = do

  (result, mbErrno) <- getExitedSyscallResult pid

  case mbErrno of
    Just errno -> return $ Left errno
    Nothing ->
      -- For the execve syscall we must not try to get the enter details at their exit,
      -- because the registers involved are invalidated.
      -- TODO: check if there are any other syscalls with such a problem.
      case knownSyscall of
        Syscall_execve | result == 0 -> do
          -- The execve() worked, we cannot get its enter details, as the
          -- registers involved are invalidated because the process image
          -- has been replaced.
          pure $ Right $ DetailedSyscallExit_execve
            SyscallExitDetails_execve{ optionalEnterDetail = Nothing, execveResult = fromIntegral result }
        _ -> do
          detailedSyscallEnter <- getSyscallEnterDetails knownSyscall syscallArgs pid
          Right <$> getSyscallExitDetails detailedSyscallEnter result pid

getSyscallExitDetails :: DetailedSyscallEnter -> Word64 -> CPid -> IO DetailedSyscallExit
getSyscallExitDetails detailedSyscallEnter result pid =
  case detailedSyscallEnter of

    DetailedSyscallEnter_getcwd
      enterDetail@SyscallEnterDetails_getcwd{ buf } -> do
        bufContents <- peekNullTerminatedBytes (TracedProcess pid) buf
        pure $ DetailedSyscallExit_getcwd $
          SyscallExitDetails_getcwd{ enterDetail, bufContents }

    DetailedSyscallEnter_open
      enterDetail@SyscallEnterDetails_open{} -> do
        pure $ DetailedSyscallExit_open $
          SyscallExitDetails_open{ enterDetail, fd = fromIntegral result }

    DetailedSyscallEnter_openat
      enterDetail@SyscallEnterDetails_openat{} -> do
        pure $ DetailedSyscallExit_openat $
          SyscallExitDetails_openat{ enterDetail, fd = fromIntegral result }

    DetailedSyscallEnter_creat
      enterDetail@SyscallEnterDetails_creat{} -> do
        pure $ DetailedSyscallExit_creat $
          SyscallExitDetails_creat{ enterDetail, fd = fromIntegral result }

    DetailedSyscallEnter_pipe
      enterDetail@SyscallEnterDetails_pipe{ pipefd } -> do
        (readfd, writefd) <- readPipeFds pid pipefd
        pure $ DetailedSyscallExit_pipe $
          SyscallExitDetails_pipe{ enterDetail, readfd, writefd }

    DetailedSyscallEnter_pipe2
      enterDetail@SyscallEnterDetails_pipe2{ pipefd } -> do
        (readfd, writefd) <- readPipeFds pid pipefd
        pure $ DetailedSyscallExit_pipe2 $
          SyscallExitDetails_pipe2{ enterDetail, readfd, writefd }

    DetailedSyscallEnter_write
      enterDetail@SyscallEnterDetails_write{} -> do
        pure $ DetailedSyscallExit_write $
          SyscallExitDetails_write{ enterDetail, writtenCount = fromIntegral result }

    DetailedSyscallEnter_access
      enterDetail@SyscallEnterDetails_access{} -> do
        pure $ DetailedSyscallExit_access $
          SyscallExitDetails_access{ enterDetail }

    DetailedSyscallEnter_faccessat
      enterDetail@SyscallEnterDetails_faccessat{} -> do
        pure $ DetailedSyscallExit_faccessat $
          SyscallExitDetails_faccessat{ enterDetail }

    DetailedSyscallEnter_read
      enterDetail@SyscallEnterDetails_read{ buf } -> do
        bufContents <- peekBytes (TracedProcess pid) buf (fromIntegral result)
        pure $ DetailedSyscallExit_read $
          SyscallExitDetails_read{ enterDetail, readCount = fromIntegral result, bufContents }

    DetailedSyscallEnter_execve
      enterDetail@SyscallEnterDetails_execve{} -> do

        pure $ DetailedSyscallExit_execve $
          SyscallExitDetails_execve{ optionalEnterDetail = Just enterDetail, execveResult = fromIntegral result }

    DetailedSyscallEnter_close
      enterDetail@SyscallEnterDetails_close{} -> do
        pure $ DetailedSyscallExit_close $
          SyscallExitDetails_close{ enterDetail }

    DetailedSyscallEnter_rename
      enterDetail@SyscallEnterDetails_rename{} -> do
        pure $ DetailedSyscallExit_rename $
          SyscallExitDetails_rename{ enterDetail }

    DetailedSyscallEnter_renameat
      enterDetail@SyscallEnterDetails_renameat{} -> do
        pure $ DetailedSyscallExit_renameat $
          SyscallExitDetails_renameat{ enterDetail }

    DetailedSyscallEnter_renameat2
      enterDetail@SyscallEnterDetails_renameat2{} -> do
        pure $ DetailedSyscallExit_renameat2 $
          SyscallExitDetails_renameat2{ enterDetail }

    DetailedSyscallEnter_unlink
      enterDetail@SyscallEnterDetails_unlink{} -> do
        pure $ DetailedSyscallExit_unlink $
          SyscallExitDetails_unlink { enterDetail }

    DetailedSyscallEnter_unlinkat
      enterDetail@SyscallEnterDetails_unlinkat{} -> do
        pure $ DetailedSyscallExit_unlinkat $
          SyscallExitDetails_unlinkat { enterDetail }

    DetailedSyscallEnter_stat
      enterDetail@SyscallEnterDetails_stat{statbuf} -> do
        stat <- Ptrace.peek (TracedProcess pid) statbuf
        pure $ DetailedSyscallExit_stat $
          SyscallExitDetails_stat{ enterDetail, stat }

    DetailedSyscallEnter_fstat
      enterDetail@SyscallEnterDetails_fstat{statbuf} -> do
        stat <- Ptrace.peek (TracedProcess pid) statbuf
        pure $ DetailedSyscallExit_fstat $
          SyscallExitDetails_fstat{ enterDetail, stat }

    DetailedSyscallEnter_lstat
      enterDetail@SyscallEnterDetails_lstat{statbuf} -> do
        stat <- Ptrace.peek (TracedProcess pid) statbuf
        pure $ DetailedSyscallExit_lstat $
          SyscallExitDetails_lstat{ enterDetail, stat }

    DetailedSyscallEnter_newfstatat
      enterDetail@SyscallEnterDetails_newfstatat{statbuf} -> do
        stat <- Ptrace.peek (TracedProcess pid) statbuf
        pure $ DetailedSyscallExit_newfstatat $
          SyscallExitDetails_newfstatat{ enterDetail, stat }

    DetailedSyscallEnter_exit
      enterDetail@SyscallEnterDetails_exit{} -> do
        pure $ DetailedSyscallExit_exit $ SyscallExitDetails_exit { enterDetail }

    DetailedSyscallEnter_exit_group
      enterDetail@SyscallEnterDetails_exit_group{} -> do
        pure $ DetailedSyscallExit_exit_group $ SyscallExitDetails_exit_group { enterDetail }

    DetailedSyscallEnter_socket
      enterDetail@SyscallEnterDetails_socket{} -> do
        pure $ DetailedSyscallExit_socket $
          SyscallExitDetails_socket{ enterDetail, fd = fromIntegral result }

    DetailedSyscallEnter_listen
      enterDetail@SyscallEnterDetails_listen{} -> do
        pure $ DetailedSyscallExit_listen $
          SyscallExitDetails_listen{ enterDetail }

    DetailedSyscallEnter_shutdown
      enterDetail@SyscallEnterDetails_shutdown{} -> do
        pure $ DetailedSyscallExit_shutdown $
          SyscallExitDetails_shutdown{ enterDetail }

    DetailedSyscallEnter_send
      enterDetail@SyscallEnterDetails_send{} -> do
        pure $ DetailedSyscallExit_send $
          SyscallExitDetails_send{ enterDetail, numSent = fromIntegral result }

    DetailedSyscallEnter_sendto
      enterDetail@SyscallEnterDetails_sendto{} -> do
        pure $ DetailedSyscallExit_sendto $
          SyscallExitDetails_sendto{ enterDetail, numSent = fromIntegral result }

    DetailedSyscallEnter_recv
      enterDetail@SyscallEnterDetails_recv{ buf } -> do
        bufContents <- peekBytes (TracedProcess pid) buf (fromIntegral result)
        pure $ DetailedSyscallExit_recv $
          SyscallExitDetails_recv{ enterDetail, numReceived = fromIntegral result, bufContents }

    DetailedSyscallEnter_recvfrom
      enterDetail@SyscallEnterDetails_recvfrom{ buf } -> do
        bufContents <- peekBytes (TracedProcess pid) buf (fromIntegral result)
        pure $ DetailedSyscallExit_recvfrom $
          SyscallExitDetails_recvfrom{ enterDetail, numReceived = fromIntegral result, bufContents }

    DetailedSyscallEnter_socketpair
      enterDetail@SyscallEnterDetails_socketpair{ sv } -> do
        (sockfd1, sockfd2) <- readPipeFds pid sv -- TODO correct?
        pure $ DetailedSyscallExit_socketpair $
          SyscallExitDetails_socketpair{ enterDetail, sockfd1, sockfd2 }

    DetailedSyscallEnter_mmap
      enterDetail@SyscallEnterDetails_mmap{} -> do
        pure $ DetailedSyscallExit_mmap $
            SyscallExitDetails_mmap{ enterDetail, mappedArea = word64ToPtr result }

    DetailedSyscallEnter_munmap
      enterDetail@SyscallEnterDetails_munmap{} -> do
        pure $ DetailedSyscallExit_munmap $
            SyscallExitDetails_munmap{ enterDetail }

    DetailedSyscallEnter_madvise
      enterDetail@SyscallEnterDetails_madvise{} -> do
        pure $ DetailedSyscallExit_madvise $
            SyscallExitDetails_madvise{ enterDetail }

    DetailedSyscallEnter_symlink
      enterDetail@SyscallEnterDetails_symlink{} -> do
        pure $ DetailedSyscallExit_symlink $
          SyscallExitDetails_symlink{ enterDetail }

    DetailedSyscallEnter_symlinkat
      enterDetail@SyscallEnterDetails_symlinkat{} -> do
        pure $ DetailedSyscallExit_symlinkat $
          SyscallExitDetails_symlinkat{ enterDetail }

    DetailedSyscallEnter_time
      enterDetail@SyscallEnterDetails_time{} -> do
        pure $ DetailedSyscallExit_time $
          SyscallExitDetails_time
            { enterDetail
            , timeResult = fromIntegral result
            }

    DetailedSyscallEnter_brk
      enterDetail@SyscallEnterDetails_brk{} -> do
        pure $ DetailedSyscallExit_brk $
          SyscallExitDetails_brk{ enterDetail, brkResult = word64ToPtr result }

    DetailedSyscallEnter_arch_prctl
      enterDetail@SyscallEnterDetails_arch_prctl{ addr } -> do
        addrValue <- case addr of
          ArchPrctlAddrArgVal value -> pure value
          ArchPrctlAddrArgPtr ptr -> peek (TracedProcess pid) ptr
          -- this shouldn't happen so we don't want to complicate
          -- the types because of this improbable scenario
          ArchPrctlAddrArgUnknown _ -> pure 0
        pure $ DetailedSyscallExit_arch_prctl $
          SyscallExitDetails_arch_prctl{ enterDetail, addrValue }

    DetailedSyscallEnter_set_tid_address
      enterDetail@SyscallEnterDetails_set_tid_address{ } -> do
        pure $ DetailedSyscallExit_set_tid_address $
          SyscallExitDetails_set_tid_address
            { enterDetail
            , tidResult = fromIntegral result
            }

    DetailedSyscallEnter_sysinfo
      enterDetail@SyscallEnterDetails_sysinfo{ info } -> do
        sysinfo <- peek (TracedProcess pid) info
        pure $ DetailedSyscallExit_sysinfo $
          SyscallExitDetails_sysinfo{ enterDetail, sysinfo }

    DetailedSyscallEnter_poll
      enterDetail@SyscallEnterDetails_poll{ fds, nfds } -> do
        -- This capping to max int below is a consequence of nfds var being a long,
        -- while peekArray taking as an argument just an int. The assumption made
        -- in here is that the number of checked fds will be less than max int.
        let n = fromIntegral $ min nfds $ fromIntegral (maxBound :: Int)
        fdsValue <- peekArray (TracedProcess pid) n fds
        pure $ DetailedSyscallExit_poll $
          SyscallExitDetails_poll{ enterDetail, fdsValue }

    DetailedSyscallEnter_ppoll
      enterDetail@SyscallEnterDetails_ppoll{ fds, nfds } -> do
        -- This capping to max int below is a consequence of nfds var being a long,
        -- while peekArray taking as an argument just an int. The assumption made
        -- in here is that the number of checked fds will be less than max int.
        let n = fromIntegral $ min nfds $ fromIntegral (maxBound :: Int)
        fdsValue <- peekArray (TracedProcess pid) n fds
        pure $ DetailedSyscallExit_ppoll $
          SyscallExitDetails_ppoll{ enterDetail, fdsValue }

    DetailedSyscallEnter_mprotect
      enterDetail@SyscallEnterDetails_mprotect{ } -> do
        pure $ DetailedSyscallExit_mprotect $
          SyscallExitDetails_mprotect{ enterDetail }

    DetailedSyscallEnter_pkey_mprotect
      enterDetail@SyscallEnterDetails_pkey_mprotect{ } -> do
        pure $ DetailedSyscallExit_pkey_mprotect $
          SyscallExitDetails_pkey_mprotect{ enterDetail }

    DetailedSyscallEnter_sched_yield SyscallEnterDetails_sched_yield -> do
        pure $ DetailedSyscallExit_sched_yield SyscallExitDetails_sched_yield

    DetailedSyscallEnter_kill
      enterDetail@SyscallEnterDetails_kill{ } -> do
        pure $ DetailedSyscallExit_kill $
          SyscallExitDetails_kill{ enterDetail }

    DetailedSyscallEnter_clone
      enterDetail@SyscallEnterDetails_clone{ } -> do
        pure $ DetailedSyscallExit_clone $
          SyscallExitDetails_clone
            { enterDetail
            , childPid = fromIntegral result
            }

    DetailedSyscallEnter_unimplemented syscall syscallArgs ->
      pure $ DetailedSyscallExit_unimplemented syscall syscallArgs result

peekArray :: Storable a => TracedProcess -> Int -> Ptr a -> IO [a]
peekArray pid size ptr
  | size <= 0 = return []
  | otherwise = do
      arrayBytes <- Ptrace.peekBytes pid ptr (size * elemSize)
      let (tmpPtr, _, _) = BSI.toForeignPtr arrayBytes
      withForeignPtr tmpPtr (\p -> Foreign.Marshal.Array.peekArray size (castPtr p))
      where
        elemSize = sizeOf ptr

readPipeFds :: CPid -> Ptr CInt -> IO (CInt, CInt)
readPipeFds pid pipefd = do
  let fdSize = sizeOf (undefined :: CInt)
      sz = 2 * fdSize
  bytes <- peekBytes (TracedProcess pid) pipefd sz
  let (ptr, off, _size) = BSI.toForeignPtr bytes
  withForeignPtr ptr $ \p -> do
    (,) <$> peekByteOff p off <*> peekByteOff p (off + fdSize)

syscallRawEnterDetailsOnlyConduit ::
     (MonadIO m)
  => ConduitT (CPid, TraceEvent (Syscall, SyscallArgs)) (CPid, DetailedSyscallEnter) m ()
syscallRawEnterDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop SyscallEnter (KnownSyscall syscall, syscallArgs) -> do
    detailedSyscallEnter <- liftIO $ getSyscallEnterDetails syscall syscallArgs pid
    yield (pid, detailedSyscallEnter)
  _ -> return () -- skip

syscallEnterDetailsOnlyConduit ::
     (MonadIO m)
  => ConduitT (CPid, TraceEvent EnterDetails) (CPid, DetailedSyscallEnter) m ()
syscallEnterDetailsOnlyConduit = concatMapC $ \(pid, event) -> case event of
  SyscallStop SyscallEnter (KnownEnterDetails _ detailedSyscallEnter) ->
    Just (pid, detailedSyscallEnter)
  _ -> Nothing -- skip


syscallRawExitDetailsOnlyConduit ::
     (MonadIO m)
  => ConduitT
       (CPid, TraceEvent (Syscall, SyscallArgs))
       (CPid, (Either (Syscall, ERRNO) DetailedSyscallExit))
       m
       ()
syscallRawExitDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop SyscallExit (syscall@(KnownSyscall knownSyscall), syscallArgs) -> do
    eDetailed <- liftIO $ getRawSyscallExitDetails knownSyscall syscallArgs pid
    yield (pid, mapLeft (syscall, ) eDetailed)
  _ -> return () -- skip

syscallExitDetailsOnlyConduit ::
     (MonadIO m)
  => ConduitT
       (CPid, TraceEvent EnterDetails)
       (CPid, (Either (Syscall, ERRNO) DetailedSyscallExit))
       m
       ()
syscallExitDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop SyscallExit enterDetails -> do
    (result, mbErrno) <- liftIO $ getExitedSyscallResult pid
    let syscall = enterDetailsToSyscall enterDetails
    exitDetailed <- case mbErrno of
      Just errno -> return $ Left errno
      Nothing -> do
        detailed <- case enterDetails of
          KnownEnterDetails _knownSyscall detailedSyscallEnter ->
            liftIO $ getSyscallExitDetails detailedSyscallEnter result pid
          UnknownEnterDetails unknown syscallArgs ->
            return $ DetailedSyscallExit_unimplemented syscall syscallArgs unknown
        return $ Right detailed
    yield (pid, mapLeft (syscall, ) exitDetailed)
  _ -> return () -- skip

foreign import ccall unsafe "string.h strerror" c_strerror :: CInt -> IO (Ptr CChar)

-- | Like "Foreign.C.Error"'s @errnoToIOError@, but getting only the string.
strError :: ERRNO -> IO String
strError (ERRNO errno) = c_strerror errno >>= peekCString


-- TODO Make a version of this that takes a CreateProcess.
--      Note that `System.Linux.Ptrace.traceProcess` isn't good enough,
--      because it is racy:
--      It uses PTHREAD_ATTACH, which sends SIGSTOP to the started
--      process. By that time, the process may already have exited.

traceForkExecvFullPath :: [String] -> (HatraceEvent -> IO ()) -> IO ExitCode
traceForkExecvFullPath args printer = do
  let formattingSink = formatHatraceEventConduit .| CL.mapM printer .| CL.sinkNull

  (exitCode, ()) <-
    genericSourceTraceForkExecvFullPathWithSink args getEnterDetails formattingSink
  return exitCode

-- | Like the partial `T.decodeUtf8`, with `HasCallStack`.
decodeUtf8OrError :: (HasCallStack) => ByteString -> Text
decodeUtf8OrError bs = case T.decodeUtf8' bs of
  Left err -> error $ "Could not decode as UTF-8: " ++ show err ++ "; ByteString was : " ++ show bs
  Right text -> text


getFdPath :: CPid -> CInt -> IO FilePath
getFdPath pid fd = do
  let procFdPath = "/proc/" ++ show pid ++ "/fd/" ++ show fd
  readSymbolicLink procFdPath


getExePath :: CPid -> IO FilePath
getExePath pid = do
  let procExePath = "/proc/" ++ show pid ++ "/exe"
  readSymbolicLink procExePath


data FileWriteEvent
  = FileOpen ByteString -- ^ name used to open the file
  | FileWrite
  | FileClose
  | FileRename ByteString -- ^ new (target) name
  deriving (Eq, Ord, Show)

-- | Uses raw trace events to produce more focused events aimed at analysing file writes.
-- Output events are accompanied by corresponding absolute file paths.
--
-- NOTES:
-- * only calls to `write` are currently used as a marker for writes and syscalls
--   `pwrite`, `writev`, `pwritev` are not taken into account
fileWritesConduit ::
     (MonadIO m)
  => ConduitT
      (CPid, TraceEvent (Syscall, SyscallArgs))
      (FilePath, FileWriteEvent)
      m
      ()
fileWritesConduit = go
  where
    go =
      await >>= \case
        Just (pid, SyscallStop SyscallExit (KnownSyscall syscall, syscallArgs)) -> do
          detailedSyscallExit <- liftIO $ getRawSyscallExitDetails syscall syscallArgs pid
          case detailedSyscallExit of
            Right (DetailedSyscallExit_open SyscallExitDetails_open
                   { enterDetail = SyscallEnterDetails_open { pathnameBS }
                   , fd }) ->
              yieldFdEvent pid fd (FileOpen pathnameBS)
            Right (DetailedSyscallExit_openat SyscallExitDetails_openat
                   { enterDetail = SyscallEnterDetails_openat { pathnameBS }
                   , fd }) ->
              yieldFdEvent pid fd (FileOpen pathnameBS)
            Right (DetailedSyscallExit_creat SyscallExitDetails_creat
                   { enterDetail = SyscallEnterDetails_creat { pathnameBS }
                   , fd }) ->
              yieldFdEvent pid fd (FileOpen pathnameBS)
            _ -> return ()
          go
        Just (pid, SyscallStop SyscallEnter (KnownSyscall syscall, syscallArgs)) -> do
          detailedSyscallEnter <- liftIO $ getSyscallEnterDetails syscall syscallArgs pid
          case detailedSyscallEnter of
            DetailedSyscallEnter_write SyscallEnterDetails_write { fd } ->
              yieldFdEvent pid fd FileWrite
            DetailedSyscallEnter_close SyscallEnterDetails_close { fd } ->
              yieldFdEvent pid fd FileClose
            DetailedSyscallEnter_rename SyscallEnterDetails_rename { oldpathBS, newpathBS } -> do
              path <- liftIO $ resolveToPidCwd pid (T.unpack $ decodeUtf8OrError oldpathBS)
              yield (path, FileRename newpathBS)
            _ -> return ()
          go
        Just _ ->
          go -- ignore other events
        Nothing ->
          return ()
    yieldFdEvent pid fd event = do
      path <- liftIO $ getFdPath pid fd
      yield (path, event)

resolveToPidCwd :: Show a => a -> FilePath -> IO FilePath
resolveToPidCwd pid path = do
  let procFdPath = "/proc/" ++ show pid ++ "/cwd"
  wd <- liftIO $ readSymbolicLink procFdPath
  canonicalizePath $ wd </> path


data FileWriteBehavior
  = NoWrites
  | NonatomicWrite
  | AtomicWrite FilePath
  -- ^ path tells temporary file name that was used
  | Unexpected String
  deriving (Eq, Ord, Show)

-- uses state machine implemented as recursive functions
analyzeWrites :: [FileWriteEvent] -> FileWriteBehavior
analyzeWrites es = checkOpen es
  where
    checkOpen events =
      case events of
        [] -> NoWrites
        -- we could see a `close` syscall for a pipe descriptor
        -- with no `open` for it thus we just ignore it
        FileClose : rest -> checkOpen rest
        FileOpen _ : rest -> checkWrites rest
        unexpected : _ -> unexpectedEvent "FileOpen" unexpected
    checkWrites events =
      case events of
        [] -> Unexpected $ "FileClose was expected but not seen"
        FileClose : rest -> checkOpen rest
        FileWrite : rest -> checkAfterWrite rest
        unexpected : _ -> unexpectedEvent "FileClose or FileWrite" unexpected
    checkAfterWrite events =
      case events of
        [] -> Unexpected $ "FileClose was expected but not seen"
        FileWrite : rest -> checkAfterWrite rest
        FileClose : rest -> checkRename rest
        unexpected : _ -> unexpectedEvent "FileClose or FileWrite" unexpected
    -- when it happens that a path gets more than 1 sequence open-write-close
    -- for it we need to check whether there was a `rename` after the 1st one
    -- and then check the result of the next one and combine them accordingly
    -- e.g. atomic + non-atomic -> non-atomic
    checkRename events =
      case events of
        FileRename path : rest ->
          case checkOpen rest of
            NoWrites ->
              -- we write original path here which swapped
              -- with oldpath in `atomicWritesSink`
              AtomicWrite (T.unpack $ decodeUtf8OrError path)
            other ->
              other
        noRenames ->
          case checkOpen noRenames of
            NoWrites -> NonatomicWrite
            other -> other
    unexpectedEvent expected real =
      Unexpected $ "expected " ++ expected ++ ", but " ++
                   show real ++ " was seen"

atomicWritesSink ::
     (MonadIO m)
  => ConduitT (CPid, TraceEvent (Syscall, SyscallArgs)) Void m (Map FilePath FileWriteBehavior)
atomicWritesSink =
  extract <$> (fileWritesConduit .| foldlC collectWrite Map.empty)
  where
    collectWrite :: Map FilePath [FileWriteEvent] -> (FilePath, FileWriteEvent) -> Map FilePath [FileWriteEvent]
    collectWrite m (fp, e) = Map.alter (Just . maybe [e] (e:)) fp m
    extract :: Map FilePath [FileWriteEvent] -> Map FilePath FileWriteBehavior
    extract m =
      let (noRenames, renames) =
            partitionEithers . map (analyzeWrites' . second reverse) $ Map.toList m
      in Map.fromList noRenames <> Map.fromList (map (second AtomicWrite) renames)
    -- this function (in addition to what `analyzeWrites` does) treats atomic writes
    -- in a special way: those include a rename and we need to put atomic writes under
    -- a path which is a target of a corresponding rename
    -- so in the end we swap path in `AtomicWrite` and its corresponding map key
    analyzeWrites' (src, es) = case analyzeWrites es of
      AtomicWrite target -> Right (target, src)
      other -> Left (src, other)

data HatraceEvent = HatraceEvent CPid EventDetails
  deriving (Eq, Ord, Show)

data EventDetails
  = EventSyscallEnter EventSyscallEnterDetails
  | EventSyscallExit EventSyscallExitDetails
  | EventPTraceEvent PTRACE_EVENT
  | EventGroupStop Signal
  | EventSignalDelivery Signal
  | EventProcessDeath ExitCode
  deriving (Eq, Ord, Show)

data EventSyscallEnterDetails = EventSyscallEnterDetails
  { evEnterDetails :: EnterDetails
  , evEnterFormatted :: FormattedSyscall
  } deriving (Eq, Ord, Show)

instance ToJSON EventSyscallEnterDetails where
  toJSON = toJSON . evEnterFormatted

data EventSyscallExitDetails = EventSyscallExitDetails
  { evExitDetails :: ExitDetails
  , evExitFormatted :: FormattedSyscall
  , evExitOutcome :: ReturnOrErrno
  } deriving (Eq, Ord, Show)

instance ToJSON EventSyscallExitDetails where
  toJSON details = object [ "syscall" .= evExitFormatted details
                          , "outcome" .= evExitOutcome details
                          ]

instance ToJSON HatraceEvent where
  toJSON (HatraceEvent pid details) =
    case details of
      EventSyscallEnter enterDetails -> formatDetails "syscall_enter" enterDetails
      EventSyscallExit exitDetails -> formatDetails "syscall_exit" exitDetails
      EventPTraceEvent ptraceEvent -> formatDetails "ptrace_event" ptraceEvent
      EventGroupStop signal -> formatDetails "group_stop" (signalToJSON signal)
      EventSignalDelivery signal -> formatDetails "signal_delivery" (signalToJSON signal)
      EventProcessDeath exitCode -> formatDetails "process_death" (exitCodeToJSON exitCode)
    where
      formatDetails eventType eventDetails =
        object [ "pid" .= toInteger pid, eventType .= eventDetails ]
      -- TODO: we need use better type than unix's barebone Signal equal to CInt
      signalToJSON = show
      -- TODO: use something better
      exitCodeToJSON = show

data ReturnOrErrno
  = ProperReturn FormattedReturn
  | ErrnoResult ERRNO String
  deriving (Eq, Ord, Show)

instance ToJSON ReturnOrErrno where
  toJSON (ProperReturn r) = object [ "return" .= r ]
  toJSON (ErrnoResult (ERRNO errno) descr) =
    object [ "error" .= object [ "errno" .= toInteger errno
                               , "description" .= descr
                               ]
           ]

formatHatraceEventConduit ::
     (MonadIO m)
  => ConduitT (CPid, TraceEvent EnterDetails) HatraceEvent m ()
formatHatraceEventConduit = CL.mapM $ \(pid, event) -> do
  case event of

    SyscallStop enterOrExit enterDetails -> do
      case enterOrExit of
        SyscallEnter -> do
          let formatted = formatSyscallEnter enterDetails
          return $ HatraceEvent pid (EventSyscallEnter $ EventSyscallEnterDetails enterDetails formatted)
        SyscallExit -> do
          (exitDetails, formatted, outcome) <- liftIO $ formatSyscallExit enterDetails pid
          return $ HatraceEvent pid (EventSyscallExit $ EventSyscallExitDetails exitDetails formatted outcome)

    PTRACE_EVENT_Stop ptraceEvent ->
      return $ HatraceEvent pid (EventPTraceEvent ptraceEvent)

    GroupStop sig ->
      return $ HatraceEvent pid (EventGroupStop sig)

    SignalDeliveryStop sig ->
      return $ HatraceEvent pid (EventSignalDelivery sig)

    Death fullStatus ->
      return $ HatraceEvent pid (EventProcessDeath fullStatus)

printHatraceEvent :: StringFormattingOptions -> HatraceEvent -> IO ()
printHatraceEvent formattingOptions (HatraceEvent pid details) = do
  putStr $ show [pid] ++ " "
  case details of
    EventSyscallEnter syscallDetails ->
      let syscall = enterDetailsToSyscall $ evEnterDetails syscallDetails
          formattedSyscall = evEnterFormatted syscallDetails
      in putStrLn $ "Entering syscall: " ++ show syscall ++ ", details: " ++
           syscallToString formattingOptions formattedSyscall

    EventSyscallExit syscallDetails ->
      let syscall = exitDetailsToSyscall $ evExitDetails syscallDetails
          formattedSyscall = evExitFormatted syscallDetails
          outcome = case evExitOutcome syscallDetails of
            ProperReturn formattedReturn -> formattedReturn
            ErrnoResult _errno strErr ->
              FormattedReturn $ FixedStringArg $ "-1 (" ++ strErr ++ ")"
      in putStrLn $ "Exited syscall: " ++ show syscall ++ ", details: " ++
        syscallExitToString formattingOptions (formattedSyscall, outcome)

    EventPTraceEvent ptraceEvent ->
      putStrLn $ "Got event: " ++ show ptraceEvent

    EventGroupStop sig ->
      putStrLn $ "Got group stop: " ++ prettySignal sig

    EventSignalDelivery sig ->
      putStrLn $ "Got signal: " ++ prettySignal sig

    EventProcessDeath exitCode ->
      putStrLn $ "Process exited with status: " ++ show exitCode


printHatraceEventJson :: HatraceEvent -> IO ()
printHatraceEventJson hatraceEvent = do
  BS.putStr $ BSL.toStrict $ encode hatraceEvent <> "\n"


formatSyscallEnter :: EnterDetails -> FormattedSyscall
formatSyscallEnter enterDetails =
  case enterDetails of
    UnknownEnterDetails number syscallArgs ->
      FormattedSyscall ("unknown_syscall_" ++ show number) (unimplementedArgs syscallArgs)
    KnownEnterDetails _knownSyscall detailed ->
      case detailed of
        DetailedSyscallEnter_getcwd details -> syscallEnterToFormatted details

        DetailedSyscallEnter_open details -> syscallEnterToFormatted details

        DetailedSyscallEnter_openat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_creat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_pipe details -> syscallEnterToFormatted details

        DetailedSyscallEnter_pipe2 details -> syscallEnterToFormatted details

        DetailedSyscallEnter_access details -> syscallEnterToFormatted details

        DetailedSyscallEnter_faccessat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_write details -> syscallEnterToFormatted details

        DetailedSyscallEnter_read details -> syscallEnterToFormatted details

        DetailedSyscallEnter_close details -> syscallEnterToFormatted details

        DetailedSyscallEnter_rename details -> syscallEnterToFormatted details

        DetailedSyscallEnter_renameat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_renameat2 details -> syscallEnterToFormatted details

        DetailedSyscallEnter_stat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_fstat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_lstat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_newfstatat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_mmap details -> syscallEnterToFormatted details

        DetailedSyscallEnter_munmap details -> syscallEnterToFormatted details

        DetailedSyscallEnter_madvise details -> syscallEnterToFormatted details

        DetailedSyscallEnter_symlink details -> syscallEnterToFormatted details

        DetailedSyscallEnter_symlinkat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_time details -> syscallEnterToFormatted details

        DetailedSyscallEnter_brk details -> syscallEnterToFormatted details

        DetailedSyscallEnter_arch_prctl details -> syscallEnterToFormatted details

        DetailedSyscallEnter_set_tid_address details -> syscallEnterToFormatted details

        DetailedSyscallEnter_sysinfo details -> syscallEnterToFormatted details

        DetailedSyscallEnter_mprotect details -> syscallEnterToFormatted details

        DetailedSyscallEnter_pkey_mprotect details -> syscallEnterToFormatted details

        DetailedSyscallEnter_execve details -> syscallEnterToFormatted details

        DetailedSyscallEnter_exit details -> syscallEnterToFormatted details

        DetailedSyscallEnter_exit_group details -> syscallEnterToFormatted details

        DetailedSyscallEnter_poll details -> syscallEnterToFormatted details

        DetailedSyscallEnter_ppoll details -> syscallEnterToFormatted details

        DetailedSyscallEnter_unlink details -> syscallEnterToFormatted details

        DetailedSyscallEnter_unlinkat details -> syscallEnterToFormatted details

        DetailedSyscallEnter_socket details -> syscallEnterToFormatted details

        DetailedSyscallEnter_listen details -> syscallEnterToFormatted details

        DetailedSyscallEnter_shutdown details -> syscallEnterToFormatted details

        DetailedSyscallEnter_send details -> syscallEnterToFormatted details

        DetailedSyscallEnter_sendto details -> syscallEnterToFormatted details

        DetailedSyscallEnter_recv details -> syscallEnterToFormatted details

        DetailedSyscallEnter_recvfrom details -> syscallEnterToFormatted details

        DetailedSyscallEnter_socketpair details -> syscallEnterToFormatted details

        DetailedSyscallEnter_sched_yield details -> syscallEnterToFormatted details

        DetailedSyscallEnter_kill details -> syscallEnterToFormatted details

        DetailedSyscallEnter_clone details -> syscallEnterToFormatted details

        DetailedSyscallEnter_unimplemented unimplementedSyscall unimplementedSyscallArgs ->
          FormattedSyscall ("unimplemented_syscall_details(" ++ show unimplementedSyscall ++ ")")
                           (unimplementedArgs unimplementedSyscallArgs)

unimplementedArgs :: SyscallArgs -> [FormattedArg]
unimplementedArgs args =
  [ formatArg (argN args) | argN <- [arg0, arg1, arg2, arg3, arg4, arg5] ]

formatSyscallExit :: EnterDetails -> CPid -> IO (ExitDetails, FormattedSyscall, ReturnOrErrno)
formatSyscallExit enterDetails pid = do
  (result, mbErrno) <- getExitedSyscallResult pid

  let unknownExit syscallArgs name = definedArgsExit name (unimplementedArgs syscallArgs)
      definedArgsExit name args = do
        err <- case mbErrno of
          Nothing -> pure $ ProperReturn NoReturn
          Just errno -> ErrnoResult errno <$> strError errno
        pure (FormattedSyscall name args, err)

  case enterDetails of
    UnknownEnterDetails number syscallArgs -> do
      (formatted, outcome) <-
        unknownExit syscallArgs $ "unknown_syscall(" ++ show number ++ ")"
      pure (UnknownExitDetails number syscallArgs, formatted, outcome)

    KnownEnterDetails knownSyscall detailed -> do
      details <- getSyscallExitDetails detailed result pid
      let exitDetails = KnownExitDetails knownSyscall details
      (formatted, outcome) <-
        formatDetailedSyscallExit details $ \syscall syscallArgs _result ->
          unknownExit syscallArgs $ "unimplemented_syscall(" ++ show syscall ++ ")"
      pure (exitDetails, formatted, outcome)

formatDetailedSyscallExit ::
     DetailedSyscallExit
  -> (Syscall -> SyscallArgs -> Word64 -> IO (FormattedSyscall, ReturnOrErrno))
  -> IO (FormattedSyscall, ReturnOrErrno)
formatDetailedSyscallExit detailedExit handleUnimplemented =
  case detailedExit of
    DetailedSyscallExit_getcwd details -> formatDetails details

    DetailedSyscallExit_open details -> formatDetails details

    DetailedSyscallExit_openat details -> formatDetails details

    DetailedSyscallExit_creat details -> formatDetails details

    DetailedSyscallExit_pipe details -> formatDetails details

    DetailedSyscallExit_pipe2 details -> formatDetails details

    DetailedSyscallExit_access details -> formatDetails details

    DetailedSyscallExit_faccessat details -> formatDetails details

    DetailedSyscallExit_write details -> formatDetails details

    DetailedSyscallExit_read details -> formatDetails details

    DetailedSyscallExit_close details -> formatDetails details

    DetailedSyscallExit_rename details -> formatDetails details

    DetailedSyscallExit_renameat details -> formatDetails details

    DetailedSyscallExit_renameat2 details -> formatDetails details

    DetailedSyscallExit_stat details -> formatDetails details

    DetailedSyscallExit_fstat details -> formatDetails details

    DetailedSyscallExit_lstat details -> formatDetails details

    DetailedSyscallExit_newfstatat details -> formatDetails details

    DetailedSyscallExit_mmap details -> formatDetails details

    DetailedSyscallExit_munmap details -> formatDetails details

    DetailedSyscallExit_madvise details -> formatDetails details

    DetailedSyscallExit_symlink details -> formatDetails details

    DetailedSyscallExit_symlinkat details -> formatDetails details

    DetailedSyscallExit_time details -> formatDetails details

    DetailedSyscallExit_brk details -> formatDetails details

    DetailedSyscallExit_arch_prctl details -> formatDetails details

    DetailedSyscallExit_set_tid_address details -> formatDetails details

    DetailedSyscallExit_sysinfo details -> formatDetails details

    DetailedSyscallExit_mprotect details -> formatDetails details

    DetailedSyscallExit_pkey_mprotect details -> formatDetails details

    DetailedSyscallExit_execve details -> formatDetails details

    DetailedSyscallExit_exit details -> formatDetails details

    DetailedSyscallExit_exit_group details -> formatDetails details

    DetailedSyscallExit_poll details -> formatDetails details

    DetailedSyscallExit_ppoll details -> formatDetails details

    DetailedSyscallExit_unlink details -> formatDetails details

    DetailedSyscallExit_unlinkat details -> formatDetails details

    DetailedSyscallExit_socket details -> formatDetails details

    DetailedSyscallExit_listen details -> formatDetails details

    DetailedSyscallExit_shutdown details -> formatDetails details

    DetailedSyscallExit_send details -> formatDetails details

    DetailedSyscallExit_sendto details -> formatDetails details

    DetailedSyscallExit_recv details -> formatDetails details

    DetailedSyscallExit_recvfrom details -> formatDetails details

    DetailedSyscallExit_socketpair details -> formatDetails details

    DetailedSyscallExit_sched_yield details -> formatDetails details

    DetailedSyscallExit_kill details -> formatDetails details

    DetailedSyscallExit_clone details -> formatDetails details

    DetailedSyscallExit_unimplemented syscall syscallArgs result ->
      handleUnimplemented syscall syscallArgs result

  where
    formatDetails :: SyscallExitFormatting a => a -> IO (FormattedSyscall, ReturnOrErrno)
    formatDetails = pure . second ProperReturn . syscallExitToFormatted

procToArgv :: (HasCallStack) => FilePath -> [String] -> IO [String]
procToArgv name args = do
  exists <- doesFileExist name
  path <- if
    | exists -> pure name
    | otherwise -> do
        mbExe <- findExecutable name
        case mbExe of
          Nothing -> die $ "Cannot find executable: " ++ name
          Just path -> pure path
  pure (path:args)


traceForkProcess ::
     (HasCallStack)
  => FilePath
  -> [String]
  -> (HatraceEvent -> IO ())
  -> IO ExitCode
traceForkProcess name args printEvent = do
  argv <- procToArgv name args
  traceForkExecvFullPath argv printEvent


-- | The terminology in here is oriented on `man 2 ptrace`.
data SyscallStopType
  = SyscallEnter
  | SyscallExit
  deriving (Eq, Ord, Show)


data PTRACE_EVENT
  = PTRACE_EVENT_VFORK CPid -- ^ PID of the new child
  | PTRACE_EVENT_FORK CPid -- ^ PID of the new child
  | PTRACE_EVENT_CLONE CPid -- ^ PID of the new child
  | PTRACE_EVENT_VFORK_DONE CPid -- ^ PID of the new child
  | PTRACE_EVENT_EXEC
  | PTRACE_EVENT_EXIT
  | PTRACE_EVENT_STOP
  | PTRACE_EVENT_SECCOMP
  | PTRACE_EVENT_OTHER -- TODO make this carry the number
  deriving (Eq, Ord, Show)


instance ToJSON PTRACE_EVENT where
  toJSON = \case
    PTRACE_EVENT_VFORK pid -> object [ "PTRACE_EVENT_VFORK" .= show pid ]
    PTRACE_EVENT_FORK pid -> object [ "PTRACE_EVENT_FORK" .= show pid ]
    PTRACE_EVENT_CLONE pid -> object [ "PTRACE_EVENT_CLONE" .= show pid ]
    PTRACE_EVENT_VFORK_DONE pid -> object [ "PTRACE_EVENT_VFORK_DONE" .= show pid ]
    PTRACE_EVENT_EXEC -> "PTRACE_EVENT_EXEC"
    PTRACE_EVENT_EXIT -> "PTRACE_EVENT_EXIT"
    PTRACE_EVENT_STOP -> "PTRACE_EVENT_STOP"
    PTRACE_EVENT_SECCOMP -> "PTRACE_EVENT_SECCOMP"
    PTRACE_EVENT_OTHER -> "PTRACE_EVENT_OTHER"


-- | The terminology in here is oriented on `man 2 ptrace`.
data TraceEvent stopDetails
  = SyscallStop SyscallStopType stopDetails
  | PTRACE_EVENT_Stop PTRACE_EVENT -- TODO change this to carry detail information with each event, e.g. what pid was clone()d
  | GroupStop Signal
  | SignalDeliveryStop Signal
  | Death ExitCode -- ^ @exit()@ or killed by signal; means the PID has vanished from the system now
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
data TraceState enterDetails = TraceState
  { currentSyscalls :: !(Map CPid enterDetails) -- ^ must be removed from the map if (it's present and the next @ptrace()@ invocation is not @PTRACE_SYSCALL@)
  } deriving (Eq, Ord, Show)


initialTraceState :: TraceState a
initialTraceState =
  TraceState
    { currentSyscalls = Map.empty
    }


-- Observing ptrace events
--
-- As per `man 2 ptrace`:
--
--     If the tracer sets PTRACE_O_TRACE_* options, the tracee will enter ptrace-stops called PTRACE_EVENT stops.
--
--     PTRACE_EVENT stops are observed by the tracer as waitpid(2) returning with
--     WIFSTOPPED(status), and WSTOPSIG(status) returns SIGTRAP. An additional bit
--     is set in the higher byte of the status word: the value `status>>8` will be
--
--         (SIGTRAP | PTRACE_EVENT_foo << 8).
--
-- Note that this only happens for when `PTRACE_O_TRACE_*` was enabled
-- for each corresponding event (`ptrace_setoptions` in Haskell).

-- Exting children:
--
-- As per `man 2 ptrace`:
--
--     PTRACE_EVENT_EXIT
--         Stop before exit (including death from exit_group(2)),
--         signal death, or exit caused by execve(2) in a multi‐ threaded process.
--         PTRACE_GETEVENTMSG returns the exit status. Registers can be examined
--         (unlike when "real" exit happens).
--         The tracee is still alive; it needs to be PTRACE_CONTed
--         or PTRACE_DETACHed to finish exiting.


-- TODO: Use these values from the `linux-ptrace` package instead.


_PTRACE_EVENT_FORK :: CInt
_PTRACE_EVENT_FORK = 1

_PTRACE_EVENT_VFORK :: CInt
_PTRACE_EVENT_VFORK = 2

_PTRACE_EVENT_CLONE :: CInt
_PTRACE_EVENT_CLONE = 3

_PTRACE_EVENT_EXEC :: CInt
_PTRACE_EVENT_EXEC = 4

_PTRACE_EVENT_VFORKDONE :: CInt
_PTRACE_EVENT_VFORKDONE = 5

_PTRACE_EVENT_EXIT :: CInt
_PTRACE_EVENT_EXIT = 6

_PTRACE_EVENT_STOP :: CInt
_PTRACE_EVENT_STOP = 128


-- TODO Don't rely on this symbol from the `linux-ptrace` package
foreign import ccall safe "ptrace" c_ptrace :: CInt -> CPid -> Ptr a -> Ptr b -> IO CLong


-- TODO: Use this values from the `linux-ptrace` package instead.
_PTRACE_GETSIGINFO :: CInt
_PTRACE_GETSIGINFO = 0x4202


-- | Uses @PTRACE_GETSIGINFO@ to check whether the current stop is a
-- group-stop.
--
-- PRE:
-- Must be called only if we're in a ptrace-stop and the signal is one
-- of SIGSTOP, SIGTSTP, SIGTTIN, or SIGTTOU (as per @man 2 ptrace@).
ptrace_GETSIGINFO_isGroupStop :: CPid -> IO Bool
ptrace_GETSIGINFO_isGroupStop pid = alloca $ \ptr -> do
  -- From `man 2 ptrace`:
  --     ptrace(PTRACE_GETSIGINFO, pid, 0, &siginfo)
  --     ...
  --     If PTRACE_GETSIGINFO fails with EINVAL,
  --     then it is definitely a group-stop.
  resetErrno -- ptrace() requires setting errno to 0 before the call
  res <- c_ptrace _PTRACE_GETSIGINFO pid (wordPtrToPtr 0) (ptr :: Ptr ())
  errno <- getErrno
  pure $ res == -1 && errno == eINVAL


waitForTraceEvent ::
     (HasCallStack)
  => TraceState a
  -> (CPid -> IO a)
  -> IO (TraceState a, (CPid, TraceEvent a))
waitForTraceEvent state@TraceState{ currentSyscalls } getDetails = do

  -- Using `AllChildren` (`__WALL`), as `man 2 ptrace` recommends and
  -- like `strace` does.
  mr <- waitpidFullStatus (-1) [AllChildren]
  case mr of
    -- This can occur when the caller incorrectly runs this on a non-traced process
    -- that exited by itself.
    Nothing -> error "waitForTraceEvent: no PID was returned by waitpid"
    Just (returnedPid, status, FullStatus fullStatus) -> do -- TODO must we have different logic if any other pid (e.g. thread, child process of traced process) was returned?
      -- What event occurred; loop if not a syscall or signal
      (newState, event) <- case status of
        -- `Exited` means that the process chose to exit by itself,
        -- as in calling `exit()` (as opposed to e.g. getting killed
        -- by a signal).
        Exited i -> do
          case i of
            0 -> pure (state, Death $ ExitSuccess)
            _ -> pure (state, Death $ ExitFailure i)
        Continued -> error $ "waitForTraceEvent: BUG: Continued status appeared even though WCONTINUE was not passed to waitpid"
        -- Note that `Signaled` means that the process was *terminated*
        -- by a signal.
        -- Signals that come in without killing the process appear in
        -- the `Stopped` case.
        Signaled _sig -> pure (state, Death $ ExitFailure (fromIntegral fullStatus))
        Stopped sig -> do
          let signalAllowsGroupStop =
                -- As per `man 2 ptrace`, only these signals are stopping
                -- signals and allow group stops.
                sig `elem` [sigSTOP, sigTSTP, sigTTIN, sigTTOU]
          isGroupStop <-
            if not signalAllowsGroupStop
              then pure False
              else ptrace_GETSIGINFO_isGroupStop returnedPid

          if
            | sig == (sigTRAP .|. 0x80) -> case Map.lookup returnedPid currentSyscalls of
                Just callAndArgs -> pure (state{ currentSyscalls = Map.delete returnedPid currentSyscalls }, SyscallStop SyscallExit callAndArgs)
                Nothing -> do
                  callAndArgs <- getDetails returnedPid
                  pure (state{ currentSyscalls = Map.insert returnedPid callAndArgs currentSyscalls }, SyscallStop SyscallEnter callAndArgs)
            | sig == sigTRAP -> if
                -- For each special PTRACE_EVENT_* we want to catch here,
                -- remember in needs to be enabled first via `ptrace_setoptions`.

                -- Note: One way of many:
                -- Technically we already know that it's `sigTRAP`,
                -- from just above (`waitpidFullStatus` does the the same masking
                -- we do here). `strace` just does an equivalent `switch` on
                -- `status >> 16` to check the `PTRACE_EVENT_*` values).
                -- We express it as `(status>>8) == (SIGTRAP | PTRACE_EVENT_foo << 8)`
                -- because that's how the `ptrace` man page expresses this check.
                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_EXIT `shiftL` 8)) -> do
                    -- As discussed above, the child is still alive when
                    -- this happens, and termination will only occur after
                    -- the child is restarted with ptrace().
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_EXIT)

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_CLONE `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_CLONE (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_FORK `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_FORK (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_VFORK `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_VFORK (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_VFORKDONE `shiftL` 8)) -> do
                    newPid <- ptrace_geteventmsg returnedPid
                    pure (state, PTRACE_EVENT_Stop (PTRACE_EVENT_VFORK_DONE (fromIntegral newPid)))

                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_EXEC `shiftL` 8)) -> do
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_EXEC)

                | otherwise -> do
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_OTHER)

            | isGroupStop -> do
                pure (state, GroupStop sig)

            | otherwise -> do
                -- A signal was sent towards the tracee.
                -- We tell the caller about it, so they can deliver it or
                -- filter it away (chosen by whether they pass it to their
                -- next `ptrace_*` (e.g. `ptrace_syscall`) invocation.
                return (state, SignalDeliveryStop sig) -- continue waiting for syscall

      return (newState, (returnedPid, event))


prettySignal :: Signal -> String
prettySignal s =
  case Map.lookup s signalMap of
    Nothing -> "Unknown signal: " ++ show s
    Just (_longName, shortName) -> shortName


data Syscall
  = KnownSyscall KnownSyscall
  | UnknownSyscall !Word64
  deriving (Eq, Ord, Show)


data SyscallArgs = SyscallArgs
  { arg0 :: !Word64
  , arg1 :: !Word64
  , arg2 :: !Word64
  , arg3 :: !Word64
  , arg4 :: !Word64
  , arg5 :: !Word64
  } deriving (Eq, Ord, Show)


-- A good resource for syscall numbers across all architectures is
-- https://fedora.juszkiewicz.com.pl/syscalls.html

syscallNumberToName_i386 :: Word32 -> Syscall
syscallNumberToName_i386 number =
  case Map.lookup number syscallMap_i386 of
    Just syscall -> KnownSyscall syscall
    Nothing -> UnknownSyscall (fromIntegral number)


syscallNumberToName_x64_64 :: Word64 -> Syscall
syscallNumberToName_x64_64 number =
  case Map.lookup number syscallMap_x64_64 of
    Just syscall -> KnownSyscall syscall
    Nothing -> UnknownSyscall number


-- | Returns the syscall that we just entered after
-- `waitForTraceEvent`.
--
-- PRE:
-- This must be called /only/ after `waitForTraceEvent` made us
-- /enter/ a syscall;
-- otherwise it may throw an `error` when trying to decode opcodes.
getEnteredSyscall :: CPid -> IO (Syscall, SyscallArgs)
getEnteredSyscall cpid = do
  regs <- annotatePtrace "getEnteredSyscall: ptrace_getregs" $ ptrace_getregs cpid
  case regs of
    X86 regs_i386@X86Regs{ orig_eax } -> do
      let syscall = syscallNumberToName_i386 orig_eax
      let args =
            SyscallArgs
              { arg0 = fromIntegral $ ebx regs_i386
              , arg1 = fromIntegral $ ecx regs_i386
              , arg2 = fromIntegral $ edx regs_i386
              , arg3 = fromIntegral $ esi regs_i386
              , arg4 = fromIntegral $ edi regs_i386
              , arg5 = fromIntegral $ ebp regs_i386
              }
      pure (syscall, args)
    X86_64 regs_x86_64@X86_64Regs{ orig_rax, rip } -> do
      -- Check whether it's an x86_64 or a legacy i386 syscall,
      -- and look up syscall number accordingly.

      -- There are 4 ways in total you can make a syscall
      -- (see https://reverseengineering.stackexchange.com/questions/2869/how-to-use-sysenter-under-linux/2894#2894):
      --
      -- - `int $0x80`
      -- - `sysenter` (i586)
      -- - `call *%gs:0x10` (vdso trampoline)
      -- - `syscall` (amd64)
      --
      -- On 32-bit x86 Linux the vdso trampoline prefers `sysenter` over
      -- `int 0x80` when possible.
      -- See also: https://github.com/systemd/systemd/issues/11974

      -- TODO: Implement we need to implement a check for `sysenter` below,
      --       so that we cover all possible ways.

      -- Both the `syscall` instruction and the `int 0x80` instruction
      -- are 2 Bytes:
      --   syscall opcode: 0x0F 0x05
      --   int 0x80 opcode: 0xCD 0x80
      -- See
      --   https://www.felixcloutier.com/x86/syscall
      --   https://www.felixcloutier.com/x86/intn:into:int3:int1
      let syscallLocation = word64ToPtr (rip - 2) -- Word is Word64 on this arch
      -- Note: `peekBytes` has a little-endian-assumption comment in it;
      -- this may not work on big-endian (I haven't checked it)
      opcode <- peekBytes (TracedProcess cpid) syscallLocation 2

      let is_i386_mode = case opcode of
            "\x0F\x05" -> False
            "\xCD\x80" -> True
            _ -> error $ "getEnteredSyscall: BUG: Unexpected syscall opcode: " ++ show opcode

      -- We don't implement x32 support any more, because it may
      -- be removed from the Kernel soon:
      -- https://lkml.org/lkml/2018/12/10/1151

      let (syscallNumber, args) = if
            | is_i386_mode ->
                ( syscallNumberToName_i386 (fromIntegral orig_rax)
                , SyscallArgs
                    { arg0 = fromIntegral $ rbx regs_x86_64
                    , arg1 = fromIntegral $ rcx regs_x86_64
                    , arg2 = fromIntegral $ rdx regs_x86_64
                    , arg3 = fromIntegral $ rsi regs_x86_64
                    , arg4 = fromIntegral $ rdi regs_x86_64
                    , arg5 = fromIntegral $ rbp regs_x86_64
                    }
                )
            | otherwise ->
                ( syscallNumberToName_x64_64 orig_rax
                , SyscallArgs
                    { arg0 = rdi regs_x86_64
                    , arg1 = rsi regs_x86_64
                    , arg2 = rdx regs_x86_64
                    , arg3 = r10 regs_x86_64
                    , arg4 = r8 regs_x86_64
                    , arg5 = r9 regs_x86_64
                    }
                )
      pure (syscallNumber, args)

-- The opcode detection method idea above was motivated by:
--
-- * Michael Bishop (`clever` on freenode)
-- * strace (where it was subsequently removed)
--   * https://superuser.com/questions/834122/how-to-distinguish-syscalls-form-int-80h-when-using-ptrace/1403397#1403397
--   * removal: https://github.com/strace/strace/commit/1f84eefc409291354d0dc7db0866eaf27967da42#diff-3abc305048b4c1c134d1cd2e0eb7799eL113
-- * Linus Torvalds in https://lore.kernel.org/lkml/CA+55aFzcSVmdDj9Lh_gdbz1OzHyEm6ZrGPBDAJnywm2LF_eVyg@mail.gmail.com/


-- | Returns the result of a syscall that we just exited after
-- `waitForTraceEvent`, and the `errno` value on failure.
--
-- Note that the kernel has no concept of `errno`, that is a libc concept.
-- But `strace` and `man 2` syscall pages have the concept. Resources:
--
-- * https://nullprogram.com/blog/2016/09/23/
-- * https://github.com/strace/strace/blob/6170252adc146638c283705c9f252cde66ac224e/linux/x86_64/get_error.c#L26-L28
-- * https://github.com/strace/strace/blob/6170252adc146638c283705c9f252cde66ac224e/negated_errno.h#L13-L14
--
-- PRE:
-- This must be called /only/ after `waitForTraceEvent` made us
-- /exit/ a syscall;
-- the returned values may be memory garbage.
getExitedSyscallResult :: CPid -> IO (Word64, Maybe ERRNO)
getExitedSyscallResult cpid = do
  regs <- annotatePtrace "getExitedSyscallResult: ptrace_getregs" $ ptrace_getregs cpid
  let retVal = case regs of
        X86 X86Regs{ eax } -> fromIntegral eax
        X86_64 X86_64Regs{ rax } -> rax
  -- Using the same logic as musl libc here to translate Linux error return
  -- values into `-1` an `errno`:
  --     https://git.musl-libc.org/cgit/musl/tree/src/internal/syscall_ret.c?h=v1.1.15
  pure $
    if retVal > fromIntegral (-4096 :: CULong)
      then (fromIntegral (-1 :: Int), Just $ ERRNO $ fromIntegral (-retVal))
      else (retVal, Nothing)

-- | Changes result of current syscall. Should be called only on exit event.
-- For 32-bit architectures Word64 type is too large, so only the last 32 bits will be used.
setExitedSyscallResult :: CPid -> Either ERRNO Word64 -> IO ()
setExitedSyscallResult cpid errorOrRetValue = do
  let newRetValue =
        case errorOrRetValue of
          Right num -> num
          Left (ERRNO errno) -> fromIntegral (-errno)
  regs <- annotatePtrace "setExitedSyscallResult: ptrace_getregs" $ ptrace_getregs cpid
  let newRegs =
        case regs of
          X86 r -> X86 r { eax = fromIntegral newRetValue }
          X86_64 r -> X86_64 r { rax = newRetValue }
  annotatePtrace "setExitedSyscallResult: ptrace_setregs" $ ptrace_setregs cpid newRegs

foreign import ccall safe "kill" c_kill :: CPid -> Signal -> IO CInt


-- | Sends a signal to a PID the standard way (via @kill()@, not via ptrace).
sendSignal :: CPid -> Signal -> IO ()
sendSignal pid signal = do
  throwErrnoIfMinus1_ "kill" $ c_kill pid signal


-- TODO: Get thise via .hsc or `posix-waitpid` instead

_WNOHANG :: CInt
_WNOHANG = 1

_WUNTRACED :: CInt
_WUNTRACED = 2

_WCONTINUED :: CInt
_WCONTINUED = 8

__WALL :: CInt
__WALL = 0x40000000


-- TODO: Don't rely on this symbol of the posix-waitpid package
foreign import ccall safe "SystemPosixWaitpid_waitpid" c_waitpid :: CPid -> Ptr CInt -> Ptr CInt -> CInt -> IO CPid


doesProcessHaveChildren :: IO Bool
doesProcessHaveChildren = alloca $ \resultPtr -> alloca $ \fullStatusPtr -> do
  -- Non-blocking request, and we want to know of *any* child's existence.
  -- Using `__WALL`, as `man 2 ptrace` recommends and like `strace` does.
  let options = _WNOHANG .|. _WUNTRACED .|. _WCONTINUED .|. __WALL
  res <- c_waitpid (-1) resultPtr fullStatusPtr options
  errno <- getErrno
  if res == -1 && errno == eCHILD
    then return False
    else const True <$> throwErrnoIfMinus1 "c_waitpid" (pure res)
