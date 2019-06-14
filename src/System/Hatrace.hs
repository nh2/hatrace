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
  , sourceTraceForkExecvFullPathWithSink
  , procToArgv
  , forkExecvWithPtrace
  , printSyscallOrSignalNameConduit
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
  , DetailedSyscallEnter(..)
  , DetailedSyscallExit(..)
  , ERRNO(..)
  , foreignErrnoToERRNO
  , getSyscallEnterDetails
  , syscallEnterDetailsOnlyConduit
  , syscallExitDetailsOnlyConduit
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

import           Conduit (foldlC)
import           Control.Arrow (second)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Control.Monad.IO.Unlift (MonadUnliftIO)
import           Data.Bits ((.|.), shiftL, shiftR)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Internal as BSI
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
import           Foreign.C.Types (CInt(..), CLong(..), CULong(..), CChar(..), CSize(..))
import           Foreign.ForeignPtr (withForeignPtr)
import           Foreign.Marshal.Alloc (alloca)
import           Foreign.Marshal.Array (withArray)
import           Foreign.Marshal.Utils (withMany)
import           Foreign.Ptr (Ptr, nullPtr, wordPtrToPtr)
import           Foreign.Storable (peekByteOff, sizeOf)
import           GHC.Stack (HasCallStack, callStack, getCallStack, prettySrcLoc)
import           System.Directory (canonicalizePath, doesFileExist, findExecutable)
import           System.Exit (ExitCode(..), die)
import           System.FilePath ((</>))
import           System.IO.Error (modifyIOError, ioeGetLocation, ioeSetLocation)
import           System.Linux.Ptrace (TracedProcess(..), peekBytes, peekNullTerminatedBytes, peekNullWordTerminatedWords, detach)
import qualified System.Linux.Ptrace as Ptrace
import           System.Linux.Ptrace.Syscall hiding (ptrace_syscall, ptrace_detach)
import qualified System.Linux.Ptrace.Syscall as Ptrace.Syscall
import           System.Linux.Ptrace.Types (Regs(..))
import           System.Linux.Ptrace.X86_64Regs (X86_64Regs(..))
import           System.Linux.Ptrace.X86Regs (X86Regs(..))
import           System.Posix.Files (readSymbolicLink)
import           System.Posix.Internals (withFilePath)
import           System.Posix.Signals (Signal, sigTRAP, sigSTOP, sigTSTP, sigTTIN, sigTTOU)
import qualified System.Posix.Signals as Signals
import           System.Posix.Types (CPid(..), CMode(..))
import           System.Posix.Waitpid (waitpid, waitpidFullStatus, Status(..), FullStatus(..), Flag(..))
import           UnliftIO.Concurrent (runInBoundThread)
import           UnliftIO.IORef (newIORef, writeIORef, readIORef)

import           System.Hatrace.SyscallTables.Generated (KnownSyscall(..), syscallName, syscallMap_i386, syscallMap_x64_64)
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
sourceTraceForkExecvFullPathWithSink :: (MonadUnliftIO m) => [String] -> ConduitT (CPid, TraceEvent) Void m a -> m (ExitCode, a)
sourceTraceForkExecvFullPathWithSink args sink = runInBoundThread $ do
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
        (newState, (returnedPid, event)) <- liftIO $ waitForTraceEvent state

        yield (returnedPid, event)

        -- Cases in which we have to restart the tracee
        -- (by calling `ptrace_syscall` again).
        liftIO $ case event of
          SyscallStop _enterOrExit -> do
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
        Nothing -> error "sourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
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
            Nothing -> error "sourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
            Just (_returnedPid, status, FullStatus fullStatus) -> case status of
              Exited 0 -> pure ExitSuccess
              _ -> pure $ ExitFailure (fromIntegral fullStatus)
  return (finalExitCode, a)


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

data SyscallEnterDetails_open = SyscallEnterDetails_open
  { pathname :: Ptr CChar
  , flags :: CInt
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_open = SyscallExitDetails_open
  { enterDetail :: SyscallEnterDetails_open
  , fd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_openat = SyscallEnterDetails_openat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , flags :: CInt
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_openat = SyscallExitDetails_openat
  { enterDetail :: SyscallEnterDetails_openat
  , fd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_creat = SyscallEnterDetails_creat
  { pathname :: Ptr CChar
  , mode :: CMode
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_creat = SyscallExitDetails_creat
  { enterDetail :: SyscallEnterDetails_creat
  , fd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_pipe = SyscallEnterDetails_pipe
  { pipefd :: Ptr CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_pipe = SyscallExitDetails_pipe
  { enterDetail :: SyscallEnterDetails_pipe
  , readfd :: CInt
  , writefd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_pipe2 = SyscallEnterDetails_pipe2
  { pipefd :: Ptr CInt
  , flags :: CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_pipe2 = SyscallExitDetails_pipe2
  { enterDetail :: SyscallEnterDetails_pipe2
  , readfd :: CInt
  , writefd :: CInt
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_exit = SyscallEnterDetails_exit
  { status :: CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_exit = SyscallExitDetails_exit
  { enterDetail :: SyscallEnterDetails_exit
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_exit_group = SyscallEnterDetails_exit_group
  { status :: CInt
  } deriving (Eq, Ord, Show)

data SyscallExitDetails_exit_group = SyscallExitDetails_exit_group
  { enterDetail :: SyscallEnterDetails_exit_group
  } deriving (Eq, Ord, Show)

data SyscallEnterDetails_write = SyscallEnterDetails_write
  { fd :: CInt
  , buf :: Ptr Void
  , count :: CSize
  -- Peeked details
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_write = SyscallExitDetails_write
  { enterDetail :: SyscallEnterDetails_write
  , writtenCount :: CSize
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_read = SyscallEnterDetails_read
  { fd :: CInt
  , buf :: Ptr Void
  , count :: CSize
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_read = SyscallExitDetails_read
  { enterDetail :: SyscallEnterDetails_read
  -- Peeked details
  , readCount :: CSize
  , bufContents :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_close = SyscallEnterDetails_close
  { fd :: CInt
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_close = SyscallExitDetails_close
  { enterDetail :: SyscallEnterDetails_close
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_rename = SyscallEnterDetails_rename
  { oldpath :: Ptr CChar
  , newpath :: Ptr CChar
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_rename = SyscallExitDetails_rename
  { enterDetail :: SyscallEnterDetails_rename
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_renameat = SyscallEnterDetails_renameat
  { olddirfd :: CInt
  , oldpath :: Ptr CChar
  , newdirfd :: CInt
  , newpath :: Ptr CChar
  -- Peeked details
  , oldpathBS :: ByteString
  , newpathBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_renameat = SyscallExitDetails_renameat
  { enterDetail :: SyscallEnterDetails_renameat
  } deriving (Eq, Ord, Show)


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


data SyscallExitDetails_renameat2 = SyscallExitDetails_renameat2
  { enterDetail :: SyscallEnterDetails_renameat2
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_access = SyscallEnterDetails_access
  { pathname :: Ptr CChar
  , mode :: CInt
  -- Peeked details
  , accessMode :: FileAccessMode
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_access = SyscallExitDetails_access
  { enterDetail :: SyscallEnterDetails_access
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_faccessat = SyscallEnterDetails_faccessat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , mode :: CInt
  , flags :: CInt
  -- Peeked details
  , accessMode :: FileAccessMode
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_faccessat = SyscallExitDetails_faccessat
  { enterDetail :: SyscallEnterDetails_faccessat
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_stat = SyscallEnterDetails_stat
  { pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_stat = SyscallExitDetails_stat
  { enterDetail :: SyscallEnterDetails_stat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_fstat = SyscallEnterDetails_fstat
  { fd :: CInt
  , statbuf :: Ptr StatStruct
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_fstat = SyscallExitDetails_fstat
  { enterDetail :: SyscallEnterDetails_fstat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_lstat = SyscallEnterDetails_lstat
  { pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_lstat = SyscallExitDetails_lstat
  { enterDetail :: SyscallEnterDetails_lstat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_newfstatat = SyscallEnterDetails_newfstatat
  { dirfd :: CInt
  , pathname :: Ptr CChar
  , statbuf :: Ptr StatStruct
  , flags :: CInt
  -- Peeked details
  , pathnameBS :: ByteString
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_newfstatat = SyscallExitDetails_newfstatat
  { enterDetail :: SyscallEnterDetails_newfstatat
  -- Peeked details
  , stat :: StatStruct
  } deriving (Eq, Ord, Show)


data SyscallEnterDetails_execve = SyscallEnterDetails_execve
  { filename :: Ptr CChar
  , argv :: Ptr (Ptr CChar)
  , envp :: Ptr (Ptr CChar)
  -- Peeked details
  , filenameBS :: ByteString
  , argvList :: [ByteString]
  , envpList :: [ByteString]
  } deriving (Eq, Ord, Show)


data SyscallExitDetails_execve = SyscallExitDetails_execve
  { optionalEnterDetail :: Maybe SyscallEnterDetails_execve
  , execveResult :: CInt
  } deriving (Eq, Ord, Show)


data DetailedSyscallEnter
  = DetailedSyscallEnter_open SyscallEnterDetails_open
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
  | DetailedSyscallEnter_stat SyscallEnterDetails_stat
  | DetailedSyscallEnter_fstat SyscallEnterDetails_fstat
  | DetailedSyscallEnter_lstat SyscallEnterDetails_lstat
  | DetailedSyscallEnter_newfstatat SyscallEnterDetails_newfstatat
  | DetailedSyscallEnter_exit SyscallEnterDetails_exit
  | DetailedSyscallEnter_exit_group SyscallEnterDetails_exit_group
  | DetailedSyscallEnter_unimplemented Syscall SyscallArgs
  deriving (Eq, Ord, Show)


data DetailedSyscallExit
  = DetailedSyscallExit_open SyscallExitDetails_open
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
  | DetailedSyscallExit_stat SyscallExitDetails_stat
  | DetailedSyscallExit_fstat SyscallExitDetails_fstat
  | DetailedSyscallExit_lstat SyscallExitDetails_lstat
  | DetailedSyscallExit_newfstatat SyscallExitDetails_newfstatat
  | DetailedSyscallExit_exit SyscallExitDetails_exit
  | DetailedSyscallExit_exit_group SyscallExitDetails_exit_group
  | DetailedSyscallExit_unimplemented Syscall SyscallArgs Word64
  deriving (Eq, Ord, Show)


getSyscallEnterDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO DetailedSyscallEnter
getSyscallEnterDetails syscall syscallArgs pid = let proc = TracedProcess pid in case syscall of
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
                   , arg2 =newdirfd, arg3 = newpathAddr, arg4 = flags } = syscallArgs
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
  _ -> pure $ DetailedSyscallEnter_unimplemented (KnownSyscall syscall) syscallArgs


getSyscallExitDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO (Either ERRNO DetailedSyscallExit)
getSyscallExitDetails knownSyscall syscallArgs pid = do

  (result, mbErrno) <- getExitedSyscallResult pid

  case mbErrno of
    Just errno -> return $ Left errno
    Nothing -> Right <$> do

      -- For some syscalls we must not try to get the enter details at their exit,
      -- because the registers involved are invalidated.
      -- TODO: Address this by not re-fetching the enter details at all, but by
      --       remembering them in a PID map.
      case knownSyscall of
        Syscall_execve | result == 0 -> do
          -- The execve() worked, we cannot get its enter details, as the
          -- registers involved are invalidated because the process image
          -- has been replaced.
          pure $ DetailedSyscallExit_execve
            SyscallExitDetails_execve{ optionalEnterDetail = Nothing, execveResult = fromIntegral result }
        _ -> do
          -- For all other syscalls, we can get the enter details.

          detailedSyscallEnter <- getSyscallEnterDetails knownSyscall syscallArgs pid

          case detailedSyscallEnter of

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

            DetailedSyscallEnter_unimplemented syscall _syscallArgs ->
              pure $ DetailedSyscallExit_unimplemented syscall syscallArgs result

readPipeFds :: CPid -> Ptr CInt -> IO (CInt, CInt)
readPipeFds pid pipefd = do
  let fdSize = sizeOf (undefined :: CInt)
      sz = 2 * fdSize
  bytes <- peekBytes (TracedProcess pid) pipefd sz
  let (ptr, off, _size) = BSI.toForeignPtr bytes
  withForeignPtr ptr $ \p -> do
    (,) <$> peekByteOff p off <*> peekByteOff p (off + fdSize)

syscallEnterDetailsOnlyConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, DetailedSyscallEnter) m ()
syscallEnterDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop (SyscallEnter (KnownSyscall syscall, syscallArgs)) -> do
    detailedSyscallEnter <- liftIO $ getSyscallEnterDetails syscall syscallArgs pid
    yield (pid, detailedSyscallEnter)
  _ -> return () -- skip


syscallExitDetailsOnlyConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, (Either (Syscall, ERRNO) DetailedSyscallExit)) m ()
syscallExitDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop (SyscallExit (syscall@(KnownSyscall knownSyscall), syscallArgs)) -> do
    eDetailed <- liftIO $ getSyscallExitDetails knownSyscall syscallArgs pid
    yield (pid, mapLeft (syscall, ) eDetailed)
  _ -> return () -- skip


formatDetailedSyscallEnter :: DetailedSyscallEnter -> String
formatDetailedSyscallEnter = \case

  DetailedSyscallEnter_open
    SyscallEnterDetails_open{ pathnameBS, flags, mode } ->
      "open(" ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_openat
    SyscallEnterDetails_openat{ dirfd, pathnameBS, flags, mode } ->
      "openat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_creat
    SyscallEnterDetails_creat{ pathnameBS, mode } ->
      "creat(" ++ show pathnameBS ++ ", " ++ show mode ++ ")"

  DetailedSyscallEnter_pipe
    SyscallEnterDetails_pipe{ } ->
      "pipe([])"

  DetailedSyscallEnter_pipe2
    SyscallEnterDetails_pipe2{ flags } ->
      "pipe([], " ++ show flags ++ ")"

  DetailedSyscallEnter_access
    SyscallEnterDetails_access{ pathnameBS, accessMode } ->
      "access(" ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ")"

  DetailedSyscallEnter_faccessat
    SyscallEnterDetails_faccessat{ dirfd, pathnameBS, accessMode, flags } ->
      "faccessat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ", " ++ show flags ++")"

  DetailedSyscallEnter_write
    SyscallEnterDetails_write{ fd, bufContents, count } ->
      "write(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_read
    SyscallEnterDetails_read{ fd, count } ->
      "read(" ++ show fd ++ ", void *buf, " ++ show count ++ ")"

  DetailedSyscallEnter_close
    SyscallEnterDetails_close{ fd } ->
      "close(" ++ show fd ++ ")"

  DetailedSyscallEnter_rename
    SyscallEnterDetails_rename{ oldpathBS, newpathBS } ->
      "rename(" ++ show oldpathBS ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallEnter_renameat
    SyscallEnterDetails_renameat{ olddirfd, oldpathBS, newdirfd, newpathBS } ->
      "renameat(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallEnter_renameat2
    SyscallEnterDetails_renameat2{ olddirfd, oldpathBS, newdirfd, newpathBS, flags } ->
      "renameat2(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                 ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallEnter_stat
    SyscallEnterDetails_stat{ pathnameBS } ->
      "stat(" ++ show pathnameBS ++ ", struct stat *statbuf)"

  DetailedSyscallEnter_fstat
    SyscallEnterDetails_fstat{ fd } ->
      "fstat(" ++ show fd ++ ", struct stat *statbuf)"

  DetailedSyscallEnter_lstat
    SyscallEnterDetails_lstat{ pathnameBS } ->
      "lstat(" ++ show pathnameBS ++ ", struct stat *statbuf)"

  DetailedSyscallEnter_newfstatat
    SyscallEnterDetails_newfstatat{ dirfd, pathnameBS, flags } ->
      "newfstatat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", struct stat *statbuf, " ++ show flags ++ ")"

  DetailedSyscallEnter_execve
    SyscallEnterDetails_execve{ filenameBS, argvList, envpList } ->
      "execve(" ++ show filenameBS ++ ", " ++ show argvList ++ ", " ++ show envpList ++ ")"

  DetailedSyscallEnter_exit
    SyscallEnterDetails_exit{ status } ->
      "exit(" ++ show status ++ ")"

  DetailedSyscallEnter_exit_group
    SyscallEnterDetails_exit_group{ status } ->
      "exit_group(" ++ show status ++ ")"

  DetailedSyscallEnter_unimplemented syscall syscallArgs ->
    "unimplemented_syscall_details(" ++ show syscall ++ ", " ++ show syscallArgs ++ ")"


foreign import ccall unsafe "string.h strerror" c_strerror :: CInt -> IO (Ptr CChar)

-- | Like "Foreign.C.Error"'s @errnoToIOError@, but getting only the string.
strError :: ERRNO -> IO String
strError (ERRNO errno) = c_strerror errno >>= peekCString


formatDetailedSyscallExit :: DetailedSyscallExit -> String
formatDetailedSyscallExit = \case

  DetailedSyscallExit_open
    SyscallExitDetails_open{ enterDetail = SyscallEnterDetails_open{ pathnameBS, flags, mode }, fd } ->
      "open(" ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ") = " ++ show fd

  DetailedSyscallExit_openat
    SyscallExitDetails_openat{ enterDetail = SyscallEnterDetails_openat{ dirfd, pathnameBS, flags, mode }, fd } ->
      "openat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ show flags ++ ", " ++ show mode ++ ") = " ++ show fd

  DetailedSyscallExit_creat
    SyscallExitDetails_creat{ enterDetail = SyscallEnterDetails_creat{ pathnameBS, mode }, fd } ->
      "creat(" ++ show pathnameBS ++ ", " ++ show mode ++ ") = " ++ show fd

  DetailedSyscallExit_pipe
    SyscallExitDetails_pipe{ enterDetail = SyscallEnterDetails_pipe{}, readfd, writefd } ->
      "pipe([" ++ show readfd ++ ", " ++ show writefd ++ "])"

  DetailedSyscallExit_pipe2
    SyscallExitDetails_pipe2{ enterDetail = SyscallEnterDetails_pipe2{ flags }, readfd, writefd } ->
      "pipe([" ++ show readfd ++ ", " ++ show writefd ++ "], " ++ show flags ++ ")"

  DetailedSyscallExit_access
    SyscallExitDetails_access{ enterDetail = SyscallEnterDetails_access{ pathnameBS, accessMode } } ->
      "access(" ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ")"

  DetailedSyscallExit_faccessat
    SyscallExitDetails_faccessat
    { enterDetail = SyscallEnterDetails_faccessat{ dirfd, pathnameBS, accessMode, flags } } ->
      "faccessat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ hShow accessMode ++ ", " ++ show flags ++ ")"

  DetailedSyscallExit_write
    SyscallExitDetails_write{ enterDetail = SyscallEnterDetails_write{ fd, bufContents, count }, writtenCount } ->
      "write(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ") = " ++ show writtenCount

  DetailedSyscallExit_read
    SyscallExitDetails_read{ enterDetail = SyscallEnterDetails_read{ fd, count }, readCount, bufContents } ->
      "read(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ") = " ++ show readCount

  DetailedSyscallExit_close
    SyscallExitDetails_close{ enterDetail = SyscallEnterDetails_close{ fd } } ->
      "close(" ++ show fd ++ ")"

  DetailedSyscallExit_rename
    SyscallExitDetails_rename{ enterDetail = SyscallEnterDetails_rename{ oldpathBS, newpathBS } } ->
      "rename(" ++ show oldpathBS ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallExit_renameat
    SyscallExitDetails_renameat
    { enterDetail = SyscallEnterDetails_renameat{ olddirfd, oldpathBS, newdirfd, newpathBS } } ->
      "renameat(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ")"

  DetailedSyscallExit_renameat2
    SyscallExitDetails_renameat2
    { enterDetail = SyscallEnterDetails_renameat2{ olddirfd, oldpathBS, newdirfd, newpathBS, flags } } ->
      "renameat2(" ++ show olddirfd ++ ", " ++ show oldpathBS ++
                 ", " ++ show newdirfd ++ ", " ++ show newpathBS ++ ", " ++ show flags ++ ")"

  DetailedSyscallExit_stat
    SyscallExitDetails_stat{ enterDetail = SyscallEnterDetails_stat{ pathnameBS }, stat } ->
      "stat(" ++ show pathnameBS ++ ", " ++ hShow stat ++ ")"

  DetailedSyscallExit_fstat
    SyscallExitDetails_fstat{ enterDetail = SyscallEnterDetails_fstat{ fd }, stat } ->
      "fstat(" ++ show fd ++ ", " ++ hShow stat ++ ")"

  DetailedSyscallExit_lstat
    SyscallExitDetails_lstat{ enterDetail = SyscallEnterDetails_lstat{ pathnameBS }, stat } ->
      "lstat(" ++ show pathnameBS ++ ", " ++ hShow stat ++ ")"

  DetailedSyscallExit_newfstatat
    SyscallExitDetails_newfstatat{ enterDetail = SyscallEnterDetails_newfstatat{ dirfd, pathnameBS, flags }, stat } ->
      "newfstatat(" ++ show dirfd ++ ", " ++ show pathnameBS ++ ", " ++ hShow stat ++ ", " ++ show flags ++ ")"

  DetailedSyscallExit_execve
    SyscallExitDetails_execve{ optionalEnterDetail, execveResult } ->
      -- TODO implement remembering arguments
      let arguments = case optionalEnterDetail of
            Just SyscallEnterDetails_execve{ filenameBS, argvList, envpList } ->
              show filenameBS ++ ", " ++ show argvList ++ ", " ++ show envpList
            Nothing -> "TODO implement remembering arguments"
      in "execve(" ++ arguments ++ ") = " ++ show execveResult

  DetailedSyscallExit_exit
    SyscallExitDetails_exit{ enterDetail = SyscallEnterDetails_exit{ status }} ->
      "exit(" ++ show status ++ ")"

  DetailedSyscallExit_exit_group
    SyscallExitDetails_exit_group{ enterDetail = SyscallEnterDetails_exit_group{ status }} ->
      "exit_group(" ++ show status ++ ")"

  DetailedSyscallExit_unimplemented syscall syscallArgs result ->
    "unimplemented_syscall_details(" ++ show syscall ++ ", " ++ show syscallArgs ++ ") = " ++ show result


getFormattedSyscallEnterDetails :: Syscall -> SyscallArgs -> CPid -> IO String
getFormattedSyscallEnterDetails syscall syscallArgs pid =
  case syscall of
    UnknownSyscall number -> do
      pure $ "unknown_syscall_" ++ show number ++ "(" ++ show syscallArgs ++ ")"
    KnownSyscall knownSyscall -> do
      detailed <- getSyscallEnterDetails knownSyscall syscallArgs pid
      pure $ formatDetailedSyscallEnter detailed


getFormattedSyscallExitDetails :: Syscall -> SyscallArgs -> CPid -> IO String
getFormattedSyscallExitDetails syscall syscallArgs pid =
  case syscall of
    UnknownSyscall number -> do
      pure $ "unknown_syscall_" ++ show number ++ "(" ++ show syscallArgs ++ ")"
    KnownSyscall knownSyscall -> do

      eDetailed <- getSyscallExitDetails knownSyscall syscallArgs pid

      case eDetailed of
        Right detailedExit -> pure $ formatDetailedSyscallExit detailedExit
        Left errno -> do
          strErr <- strError errno
          let formattedErrno = " (" ++ strErr ++ ")"
          -- TODO implement remembering arguments
          pure $ syscallName knownSyscall ++ "(TODO implement remembering arguments) = -1" ++ formattedErrno


-- TODO Make a version of this that takes a CreateProcess.
--      Note that `System.Linux.Ptrace.traceProcess` isn't good enough,
--      because it is racy:
--      It uses PTHREAD_ATTACH, which sends SIGSTOP to the started
--      process. By that time, the process may already have exited.

traceForkExecvFullPath :: [String] -> IO ExitCode
traceForkExecvFullPath args = do
  (exitCode, ()) <-
    sourceTraceForkExecvFullPathWithSink args (printSyscallOrSignalNameConduit .| CL.sinkNull)
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
fileWritesConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (FilePath, FileWriteEvent) m ()
fileWritesConduit = go
  where
    go =
      await >>= \case
        Just (pid, SyscallStop (SyscallExit (KnownSyscall syscall, syscallArgs))) -> do
          detailedSyscallExit <- liftIO $ getSyscallExitDetails syscall syscallArgs pid
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
        Just (pid, SyscallStop (SyscallEnter (KnownSyscall syscall, syscallArgs))) -> do
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

atomicWritesSink :: (MonadIO m) => ConduitT (CPid, TraceEvent) Void m (Map FilePath FileWriteBehavior)
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

-- | Passes through all syscalls and signals that come by,
-- printing them, including details where available.
printSyscallOrSignalNameConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, TraceEvent) m ()
printSyscallOrSignalNameConduit = CL.iterM $ \(pid, event) -> do
  liftIO $ case event of

    SyscallStop enterOrExit -> case enterOrExit of

      SyscallEnter (syscall, syscallArgs) -> do
        formatted <- getFormattedSyscallEnterDetails syscall syscallArgs pid
        putStrLn $ show [pid] ++ " Entering syscall: " ++ show syscall
          ++ (if formatted /= "" then ", details: " ++ formatted else "")

      SyscallExit (syscall, syscallArgs) -> do
        formatted <- getFormattedSyscallExitDetails syscall syscallArgs pid
        putStrLn $ show [pid] ++ " Exited syscall: " ++ show syscall
          ++ (if formatted /= "" then ", details: " ++ formatted else "")

    PTRACE_EVENT_Stop ptraceEvent -> do
      putStrLn $ show [pid] ++ " Got event: " ++ show ptraceEvent

    GroupStop sig -> do
      putStrLn $ show [pid] ++ " Got group stop: " ++ prettySignal sig

    SignalDeliveryStop sig -> do
      putStrLn $ show [pid] ++ " Got signal: " ++ prettySignal sig

    Death fullStatus -> do
      putStrLn $ show [pid] ++ " Process exited with status: " ++ show fullStatus


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


traceForkProcess :: (HasCallStack) => FilePath -> [String] -> IO ExitCode
traceForkProcess name args = do
  argv <- procToArgv name args
  traceForkExecvFullPath argv


-- | The terminology in here is oriented on `man 2 ptrace`.
data SyscallStopType
  = SyscallEnter (Syscall, SyscallArgs)
  | SyscallExit (Syscall, SyscallArgs) -- ^ contains the args from when the syscall was entered
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


-- | The terminology in here is oriented on `man 2 ptrace`.
data TraceEvent
  = SyscallStop SyscallStopType
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
data TraceState = TraceState
  { currentSyscalls :: !(Map CPid (Syscall, SyscallArgs)) -- ^ must be removed from the map if (it's present and the next @ptrace()@ invocation is not @PTRACE_SYSCALL@)
  } deriving (Eq, Ord, Show)


initialTraceState :: TraceState
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


waitForTraceEvent :: (HasCallStack) => TraceState -> IO (TraceState, (CPid, TraceEvent))
waitForTraceEvent state@TraceState{ currentSyscalls } = do

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
                Just callAndArgs -> pure (state{ currentSyscalls = Map.delete returnedPid currentSyscalls }, SyscallStop (SyscallExit callAndArgs))
                Nothing -> do
                  callAndArgs <- getEnteredSyscall returnedPid
                  pure (state{ currentSyscalls = Map.insert returnedPid callAndArgs currentSyscalls }, SyscallStop (SyscallEnter callAndArgs))
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


signalMap :: Map Signal (String, String)
signalMap =
  Map.fromList $ map (\(s, long, short) -> (s, (long, short))) $
    [ (Signals.nullSignal, "nullSignal", "NULL")
    , (Signals.internalAbort, "internalAbort", "ABRT")
    , (Signals.realTimeAlarm, "realTimeAlarm", "ALRM")
    , (Signals.busError, "busError", "BUS")
    , (Signals.processStatusChanged, "processStatusChanged", "CHLD")
    , (Signals.continueProcess, "continueProcess", "CONT")
    , (Signals.floatingPointException, "floatingPointException", "FPE")
    , (Signals.lostConnection, "lostConnection", "HUP")
    , (Signals.illegalInstruction, "illegalInstruction", "ILL")
    , (Signals.keyboardSignal, "keyboardSignal", "INT")
    , (Signals.killProcess, "killProcess", "KILL")
    , (Signals.openEndedPipe, "openEndedPipe", "PIPE")
    , (Signals.keyboardTermination, "keyboardTermination", "QUIT")
    , (Signals.segmentationViolation, "segmentationViolation", "SEGV")
    , (Signals.softwareStop, "softwareStop", "STOP")
    , (Signals.softwareTermination, "softwareTermination", "TERM")
    , (Signals.keyboardStop, "keyboardStop", "TSTP")
    , (Signals.backgroundRead, "backgroundRead", "TTIN")
    , (Signals.backgroundWrite, "backgroundWrite", "TTOU")
    , (Signals.userDefinedSignal1, "userDefinedSignal1", "USR1")
    , (Signals.userDefinedSignal2, "userDefinedSignal2", "USR2")
    , (Signals.pollableEvent, "pollableEvent", "POLL")
    , (Signals.profilingTimerExpired, "profilingTimerExpired", "PROF")
    , (Signals.badSystemCall, "badSystemCall", "SYS")
    , (Signals.breakpointTrap, "breakpointTrap", "TRAP")
    , (Signals.urgentDataAvailable, "urgentDataAvailable", "URG")
    , (Signals.virtualTimerExpired, "virtualTimerExpired", "VTALRM")
    , (Signals.cpuTimeLimitExceeded, "cpuTimeLimitExceeded", "XCPU")
    , (Signals.fileSizeLimitExceeded, "fileSizeLimitExceeded", "XFSZ")
    ]


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
