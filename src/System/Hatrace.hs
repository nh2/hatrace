{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

module System.Hatrace
  ( traceForkProcess
  , traceForkExecvFullPath
  , sourceTraceForkExecvFullPathWithSink
  , procToArgv
  , forkExecvWithPtrace
  , printSyscallOrSignalNameConduit
  , SyscallEnterDetails_write(..)
  , SyscallExitDetails_write(..)
  , SyscallEnterDetails_read(..)
  , SyscallExitDetails_read(..)
  , DetailedSyscallEnter(..)
  , DetailedSyscallExit(..)
  , getSyscallEnterDetails
  , syscallEnterDetailsOnlyConduit
  , syscallExitDetailsOnlyConduit
  , SyscallStopType(..)
  , TraceEvent(..)
  , TraceState(..)
  , Syscall(..)
  , SyscallArgs(..)
  , sendSignal
  , doesProcessHaveChildren
  -- * Re-exports
  , KnownSyscall(..)
  ) where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.Bits ((.|.), shiftL, shiftR)
import           Data.ByteString (ByteString)
import           Data.Conduit
import qualified Data.Conduit.List as CL
import           Data.List (genericLength)
import           Data.Map (Map)
import qualified Data.Map as Map
import           Data.Word (Word32, Word64)
import           Foreign.C.Error (throwErrnoIfMinus1, throwErrnoIfMinus1_, getErrno, resetErrno, eCHILD, eINVAL)
import           Foreign.C.Types (CInt(..), CLong(..), CChar(..), CSize(..))
import           Foreign.Marshal.Alloc (alloca)
import           Foreign.Marshal.Array (withArray)
import           Foreign.Marshal.Utils (withMany)
import           Foreign.Ptr (Ptr, wordPtrToPtr)
import           GHC.Stack (HasCallStack, callStack, getCallStack, prettySrcLoc)
import           System.Directory (doesFileExist, findExecutable)
import           System.Exit (ExitCode(..), die)
import           System.IO.Error (modifyIOError, ioeGetLocation, ioeSetLocation)
import           System.Linux.Ptrace (TracedProcess(..), peekBytes, detach)
import           System.Linux.Ptrace.Syscall hiding (ptrace_syscall, ptrace_detach)
import qualified System.Linux.Ptrace.Syscall as Ptrace.Syscall
import           System.Linux.Ptrace.Types (Regs(..))
import           System.Linux.Ptrace.X86_64Regs (X86_64Regs(..))
import           System.Linux.Ptrace.X86Regs (X86Regs(..))
import           System.Posix.Internals (withFilePath)
import           System.Posix.Signals (Signal, sigTRAP, sigSTOP, sigTSTP, sigTTIN, sigTTOU)
import qualified System.Posix.Signals as Signals
import           System.Posix.Types (CPid(..))
import           System.Posix.Waitpid (waitpid, waitpidFullStatus, Status(..), FullStatus(..))
import           UnliftIO.IORef (newIORef, writeIORef, readIORef)

import           System.Hatrace.SyscallTables.Generated (KnownSyscall(..), syscallMap_i386, syscallMap_x64_64)

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
              ] ++ ": "
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


sourceTraceForkExecvFullPathWithSink :: (MonadIO m) => [String] -> ConduitT (CPid, TraceEvent) Void m a -> m (ExitCode, a)
sourceTraceForkExecvFullPathWithSink args sink = do
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
          ptrace_detach childPid
          waitpidResult <- waitpidFullStatus childPid []
          case waitpidResult of
            Nothing -> error "sourceTraceForkExecvFullPathWithSink: BUG: no PID was returned by waitpid"
            Just (_returnedPid, status, FullStatus fullStatus) -> case status of
              Exited 0 -> pure ExitSuccess
              _ -> pure $ ExitFailure (fromIntegral fullStatus)
  return (finalExitCode, a)


-- * Syscall details
--
-- __Note:__ The data types below use @DuplicateRecordFields@.
--
-- Users should also use @DuplicateRecordFields@ to avoid getting
-- @Ambiguous occurrence@ errors.


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


data DetailedSyscallEnter
  = DetailedSyscallEnter_write SyscallEnterDetails_write
  | DetailedSyscallEnter_read SyscallEnterDetails_read
  | DetailedSyscallEnter_unimplemented Syscall SyscallArgs
  deriving (Eq, Ord, Show)


data DetailedSyscallExit
  = DetailedSyscallExit_write SyscallExitDetails_write
  | DetailedSyscallExit_read SyscallExitDetails_read
  | DetailedSyscallExit_unimplemented Syscall SyscallArgs Word64
  deriving (Eq, Ord, Show)


getSyscallEnterDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO DetailedSyscallEnter
getSyscallEnterDetails syscall syscallArgs pid = case syscall of
  Syscall_write -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count } = syscallArgs
    let bufPtr = wordPtrToPtr (fromIntegral bufAddr)
    bufContents <- peekBytes (TracedProcess pid) bufPtr (fromIntegral count)
    pure $ DetailedSyscallEnter_write $ SyscallEnterDetails_write
      { fd = fromIntegral fd
      , buf = bufPtr
      , count = fromIntegral count
      , bufContents
      }
  Syscall_read -> do
    let SyscallArgs{ arg0 = fd, arg1 = bufAddr, arg2 = count } = syscallArgs
    let bufPtr = wordPtrToPtr (fromIntegral bufAddr)
    pure $ DetailedSyscallEnter_read $ SyscallEnterDetails_read
      { fd = fromIntegral fd
      , buf = bufPtr
      , count = fromIntegral count
      }
  _ -> pure $
    DetailedSyscallEnter_unimplemented (KnownSyscall syscall) syscallArgs


getSyscallExitDetails :: KnownSyscall -> SyscallArgs -> CPid -> IO DetailedSyscallExit
getSyscallExitDetails knownSyscall syscallArgs pid = do
  detailedSyscallEnter <- getSyscallEnterDetails knownSyscall syscallArgs pid
  result <- getExitedSyscallResult pid

  case detailedSyscallEnter of

    DetailedSyscallEnter_write
      enterDetail@SyscallEnterDetails_write{} -> do
        pure $ DetailedSyscallExit_write $
          SyscallExitDetails_write{ enterDetail, writtenCount = fromIntegral result }

    DetailedSyscallEnter_read
      enterDetail@SyscallEnterDetails_read{ buf } -> do
        bufContents <- peekBytes (TracedProcess pid) buf (fromIntegral result)
        pure $ DetailedSyscallExit_read $
          SyscallExitDetails_read{ enterDetail, readCount = fromIntegral result, bufContents }

    DetailedSyscallEnter_unimplemented syscall _syscallArgs ->
      pure $ DetailedSyscallExit_unimplemented syscall syscallArgs result


syscallEnterDetailsOnlyConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, DetailedSyscallEnter) m ()
syscallEnterDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop (SyscallEnter (KnownSyscall syscall, syscallArgs)) -> do
    detailedSyscallEnter <- liftIO $ getSyscallEnterDetails syscall syscallArgs pid
    yield (pid, detailedSyscallEnter)
  _ -> return () -- skip


syscallExitDetailsOnlyConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, DetailedSyscallExit) m ()
syscallExitDetailsOnlyConduit = awaitForever $ \(pid, event) -> case event of
  SyscallStop (SyscallExit (KnownSyscall syscall, syscallArgs)) -> do
    detailedSyscallEnter <- liftIO $ getSyscallExitDetails syscall syscallArgs pid
    yield (pid, detailedSyscallEnter)
  _ -> return () -- skip


formatDetailedSyscallEnter :: DetailedSyscallEnter -> String
formatDetailedSyscallEnter = \case

  DetailedSyscallEnter_write
    SyscallEnterDetails_write{ fd, bufContents, count } ->
      "write(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ")"

  DetailedSyscallEnter_read
    SyscallEnterDetails_read{ fd, count } ->
      "read(" ++ show fd ++ ", void *buf, " ++ show count ++ ")"

  DetailedSyscallEnter_unimplemented syscall syscallArgs ->
    "unimplemented_syscall_details(" ++ show syscall ++ ", " ++ show syscallArgs ++ ")"


formatDetailedSyscallExit :: DetailedSyscallExit -> String
formatDetailedSyscallExit = \case

  DetailedSyscallExit_write
    SyscallExitDetails_write{ enterDetail = SyscallEnterDetails_write{ fd, bufContents, count }, writtenCount } ->
      "write(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ") = " ++ show writtenCount

  DetailedSyscallExit_read
    SyscallExitDetails_read{ enterDetail = SyscallEnterDetails_read{ fd, count }, readCount, bufContents } ->
      "read(" ++ show fd ++ ", " ++ show bufContents ++ ", " ++ show count ++ ") = " ++ show readCount

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
      detailed <- getSyscallExitDetails knownSyscall syscallArgs pid
      pure $ formatDetailedSyscallExit detailed


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


-- | Passes through all syscalls and signals that come by,
-- printing them, including details where available.
printSyscallOrSignalNameConduit :: (MonadIO m) => ConduitT (CPid, TraceEvent) (CPid, TraceEvent) m ()
printSyscallOrSignalNameConduit = CL.mapM_ $ \(pid, event) -> do
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
  = PTRACE_EVENT_VFORK
  | PTRACE_EVENT_FORK
  | PTRACE_EVENT_CLONE
  | PTRACE_EVENT_VFORK_DONE
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

  mr <- waitpidFullStatus (-1) []
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
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_CLONE)
                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_FORK `shiftL` 8)) -> do
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_FORK)
                | (fullStatus `shiftR` 8) == (sigTRAP .|. (_PTRACE_EVENT_VFORK `shiftL` 8)) -> do
                    pure (state, PTRACE_EVENT_Stop PTRACE_EVENT_VFORK)
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

      -- Both the `syscall` instruction and the `int 0x80` instruction
      -- are 2 Bytes:
      --   syscall opcode: 0x0F 0x05
      --   int 0x80 opcode: 0xCD 0x80
      -- See
      --   https://www.felixcloutier.com/x86/syscall
      --   https://www.felixcloutier.com/x86/intn:into:int3:int1
      let syscallLocation = wordPtrToPtr (fromIntegral (rip - 2)) -- Word is Word64 on this arch
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
-- `waitForTraceEvent`.
--
-- PRE:
-- This must be called /only/ after `waitForTraceEvent` made us
-- /exit/ a syscall;
-- the returned values may be memory garbage.
getExitedSyscallResult :: CPid -> IO Word64
getExitedSyscallResult cpid = do
  regs <- annotatePtrace "getExitedSyscallResult: ptrace_getregs" $ ptrace_getregs cpid
  pure $ case regs of
    X86 X86Regs{ eax } -> fromIntegral eax
    X86_64 X86_64Regs{ rax } -> rax


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


-- TODO: Don't rely on this symbol of the posix-waitpid package
foreign import ccall safe "SystemPosixWaitpid_waitpid" c_waitpid :: CPid -> Ptr CInt -> Ptr CInt -> CInt -> IO CPid


doesProcessHaveChildren :: IO Bool
doesProcessHaveChildren = alloca $ \resultPtr -> alloca $ \fullStatusPtr -> do
  -- Non-blocking request, and we want to know of *any* child's existence.
  let options = _WNOHANG .|. _WUNTRACED .|. _WCONTINUED
  res <- c_waitpid (-1) resultPtr fullStatusPtr options
  errno <- getErrno
  if res == -1 && errno == eCHILD
    then return False
    else const True <$> throwErrnoIfMinus1 "c_waitpid" (pure res)
