{-# LANGUAGE LambdaCase #-}

#include <sys/param.h>

module System.Hatrace.FdNames
  ( resolveFdName
  ) where

import           Control.Exception (AssertionFailed (..), throwIO)
import           Foreign.C.Error (throwErrnoIfMinus1)
import           Foreign.C.String (CString, peekCString)
import           Foreign.C.Types (CInt (..))
import           Foreign.Marshal.Alloc (allocaBytes)
import           GHC.Stack (HasCallStack)
import           System.Posix.Types (CPid (..))


foreign import ccall safe "resolve_fd_name" c_resolve_fd_name :: CPid -> CInt -> CString -> IO CInt

resolveFdName :: (HasCallStack) => CPid -> CInt -> IO (Maybe FilePath)
resolveFdName pid fd =
  allocaBytes (#const MAXPATHLEN) $ \ptr -> do
    throwErrnoIfMinus1 "resolve_fd_name" (c_resolve_fd_name pid fd ptr) >>= \case
      0 -> Just <$> peekCString ptr
      1 -> pure Nothing
      _ -> throwIO $ AssertionFailed "resolveFdName: something terrible happened"
