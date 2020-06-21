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
  => ConduitT (CPid, TraceEvent (Syscall, SyscallArgs)) Void m ()
inheritedFlocksSink = do
  -- extract <$> (fileWritesConduit .| foldlC collectWrite Map.empty)
  let loop = do
        await >>= \case
          Just x -> do
            liftIO $ print x
            loop
          Nothing -> return ()
  loop
