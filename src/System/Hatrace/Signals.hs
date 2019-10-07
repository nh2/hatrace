{-# LANGUAGE CPP #-}
{-# LANGUAGE CApiFFI #-}

-- We use the `CONST_*` constants from the `unix` package to know
-- whether specific signals are supported on the current platform.
#include <HsUnixConfig.h>

module System.Hatrace.Signals
  ( allSignals
  , addSignal
  , emptySignalSet
  , fullSignalSet
  , inSignalSet
  , signalMap
  , sizeOfCSigset
  ) where

import qualified Data.List as List
import           Data.Map (Map)
import qualified Data.Map as Map
import           Foreign.C.Error (throwErrnoIfMinus1, throwErrnoIfMinus1_)
import           Foreign.C.Types (CInt(..))
import           Foreign.ForeignPtr (ForeignPtr, withForeignPtr, mallocForeignPtrBytes)
import           Foreign.Marshal (copyBytes)
import           Foreign.Ptr (Ptr)
import           System.Posix.Internals (sizeof_sigset_t, CSigset)
import           System.Posix.Signals (Signal)
import qualified System.Posix.Signals as Signals


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
#if CONST_SIGPOLL != -1
    , (Signals.pollableEvent, "pollableEvent", "POLL")
#endif
    , (Signals.profilingTimerExpired, "profilingTimerExpired", "PROF")
    , (Signals.badSystemCall, "badSystemCall", "SYS")
    , (Signals.breakpointTrap, "breakpointTrap", "TRAP")
    , (Signals.urgentDataAvailable, "urgentDataAvailable", "URG")
    , (Signals.virtualTimerExpired, "virtualTimerExpired", "VTALRM")
    , (Signals.cpuTimeLimitExceeded, "cpuTimeLimitExceeded", "XCPU")
    , (Signals.fileSizeLimitExceeded, "fileSizeLimitExceeded", "XFSZ")
    ]

sizeOfCSigset :: Int
sizeOfCSigset = sizeof_sigset_t

allSignals :: [Signals.Signal]
allSignals = List.delete Signals.nullSignal $ Map.keys signalMap

inSignalSet :: Signals.Signal -> ForeignPtr CSigset -> IO Bool
inSignalSet sig ptr = do
  withForeignPtr ptr $ \p -> do
    r <- throwErrnoIfMinus1 "inSignalSet" (c_sigismember p sig)
    return (r /= 0)

emptySignalSet :: IO (ForeignPtr CSigset)
emptySignalSet = do
  fp <- mallocForeignPtrBytes sizeof_sigset_t
  throwErrnoIfMinus1_ "emptySignalSet" (withForeignPtr fp $ c_sigemptyset)
  return fp

fullSignalSet :: IO (ForeignPtr CSigset)
fullSignalSet = do
  fp <- mallocForeignPtrBytes sizeof_sigset_t
  throwErrnoIfMinus1_ "fullSignalSet" (withForeignPtr fp $ c_sigfillset)
  return fp

addSignal :: Signals.Signal -> ForeignPtr CSigset -> IO (ForeignPtr CSigset)
addSignal sig fp1 = do
  fp2 <- mallocForeignPtrBytes sizeof_sigset_t
  withForeignPtr fp1 $ \p1 ->
    withForeignPtr fp2 $ \p2 -> do
      copyBytes p2 p1 sizeof_sigset_t
      throwErrnoIfMinus1_ "addSignal" (c_sigaddset p2 sig)
  return fp2

foreign import capi unsafe "signal.h sigismember"
  c_sigismember :: Ptr CSigset -> CInt -> IO CInt

foreign import capi unsafe "signal.h sigemptyset"
   c_sigemptyset :: Ptr CSigset -> IO CInt

foreign import capi unsafe "signal.h sigfillset"
  c_sigfillset  :: Ptr CSigset -> IO CInt

foreign import capi unsafe "signal.h sigaddset"
   c_sigaddset :: Ptr CSigset -> CInt -> IO CInt
