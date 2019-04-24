#include <unistd.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , CIntRepresentable(..)
  ) where

import           Data.Bits
import           Data.List (intercalate)
import           Foreign.C.Types (CInt(..))
                                 
class CIntRepresentable a where
  toCInt :: a -> CInt
  fromCInt :: CInt -> a

data FileAccessMode
  = FileExistence
  | GranularAccess GranularAccessMode
  | FileAccessUnknown CInt
  deriving (Eq, Ord)

instance Show FileAccessMode where
  show FileExistence = "F_OK"
  show (GranularAccess mode) =
    intercalate "|" $ concat
      [ if accessModeRead mode then ["R_OK"] else []
      , if accessModeWrite mode then ["W_OK"] else []
      , if accessModeExecute mode then ["X_OK"] else []
      ]
  show (FileAccessUnknown x) = show x

data GranularAccessMode = GranularAccessMode
  { accessModeRead :: Bool
  , accessModeWrite :: Bool
  , accessModeExecute :: Bool
  } deriving (Eq, Ord, Show)

instance CIntRepresentable FileAccessMode where
  toCInt FileExistence = (#const F_OK)
  toCInt (GranularAccess ga) = r .|. w .|. x
    where
      r = if accessModeRead ga then (#const R_OK) else 0
      w = if accessModeWrite ga then (#const W_OK) else 0
      x = if accessModeExecute ga then (#const X_OK) else 0
  toCInt (FileAccessUnknown x) = x
  fromCInt 0 = FileExistence
  fromCInt m | m .&. complement accessBits /= zeroBits = FileAccessUnknown m
             | otherwise =
                let isset f = m .&. f /= zeroBits
                in GranularAccess GranularAccessMode
                   { accessModeRead = isset (#const R_OK)
                   , accessModeWrite = isset (#const W_OK)
                   , accessModeExecute = isset (#const X_OK)
                   }
    where
      accessBits = (#const R_OK) .|. (#const W_OK) .|. (#const X_OK)
