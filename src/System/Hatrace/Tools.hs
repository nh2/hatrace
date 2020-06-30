{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE TupleSections #-}

module System.Hatrace.Tools
  ( inheritedFlocksSink
  ) where

import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.Conduit

import           System.Hatrace

inheritedFlocksSink ::
     (MonadIO m)
  => ConduitT (CPid, TraceEvent EnterDetails) Void m ()
inheritedFlocksSink = do
  -- extract <$> (fileWritesConduit .| foldlC collectWrite Map.empty)
  let loop = do
        await >>= \case
          -- Just (pid :: CPid, ev :: Either (Syscall, ERRNO) DetailedSyscallExit) -> do
          Nothing -> return ()
          Just (HatraceEvent pid (eventDetails :: EventDetails)) -> do
            case eventDetails of
              EventSyscallEnter EventSyscallEnterDetails{ evEnterDetails } -> case evEnterDetails of
                KnownEnterDetails knownSyscall (DetailedSyscallEnter_flock SyscallEnterDetails_flock{ fd, flockOperation }) -> do
                  liftIO $ print ("enter flock", fd, flockOperation)
                -- Just errno -> case syscall of
                --   KnownSyscall Syscall_flock -> liftIO $ print ("flock returned error", errno)
                --   _ -> return ()
                -- Nothing -> case enterDetails of
                --     KnownEnterDetails _knownSyscall detailedSyscallEnter -> do
                --       details <- liftIO $ getSyscallExitDetails detailedSyscallEnter result pid
                --       liftIO $ print details
                _ -> return ()

              EventSyscallExit EventSyscallExitDetails{ evExitDetails } -> case evExitDetails of
                KnownExitDetails knownSyscall _detailedSyscallEnter -> do
                  liftIO $ print ("exit", knownSyscall)
                _ -> return ()

              _ -> return ()
            loop
  formatHatraceEventConduit .| loop
