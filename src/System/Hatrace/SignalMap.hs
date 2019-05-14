{-# LANGUAGE CPP #-}

-- We use the `CONST_*` constants from the `unix` package to know
-- whether specific signals are supported on the current platform.
#include <HsUnixConfig.h>

module System.Hatrace.SignalMap
  ( signalMap
  ) where

import           Data.Map (Map)
import qualified Data.Map as Map
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
