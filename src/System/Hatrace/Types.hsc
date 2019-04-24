#include <unistd.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , GranularAccessMode(..)
  , fileExistence
  , CIntRepresentable(..)
  , HatraceShow(..)
  ) where

import           Data.Bits
import           Data.List (intercalate)
import           Foreign.C.Types (CInt(..))

-- | Helper type class for int-sized enum-like types
class CIntRepresentable a where
  toCInt :: a -> CInt
  fromCInt :: CInt -> a

data FileAccessMode
  = FileAccessKnown GranularAccessMode
  | FileAccessUnknown CInt
  deriving (Eq, Ord, Show)

-- | Hatrace-specific show type class
class HatraceShow a where
  hShow :: a -> String

instance HatraceShow FileAccessMode where
  hShow (FileAccessKnown mode) =
    let granularModes = concat
          [ if accessModeRead mode then ["R_OK"] else []
          , if accessModeWrite mode then ["W_OK"] else []
          , if accessModeExecute mode then ["X_OK"] else []
          ]
    in if null granularModes then "F_OK" else intercalate "|" granularModes
  hShow (FileAccessUnknown x) = show x

data GranularAccessMode = GranularAccessMode
  { accessModeRead :: Bool
  , accessModeWrite :: Bool
  , accessModeExecute :: Bool
  } deriving (Eq, Ord, Show)

-- | special access mode not equal to any granular access modes
-- designating just a file existence check
fileExistence :: GranularAccessMode
fileExistence = GranularAccessMode False False False

instance CIntRepresentable FileAccessMode where
  toCInt (FileAccessKnown ga) = r .|. w .|. x .|. (#const F_OK)
    where
      r = if accessModeRead ga then (#const R_OK) else 0
      w = if accessModeWrite ga then (#const W_OK) else 0
      x = if accessModeExecute ga then (#const X_OK) else 0
  toCInt (FileAccessUnknown x) = x
  fromCInt (#const F_OK) = FileAccessKnown fileExistence
  fromCInt m | (m .&. complement accessBits) /= zeroBits = FileAccessUnknown m
             | otherwise =
                let isset f = (m .&. f) /= zeroBits
                in FileAccessKnown GranularAccessMode
                   { accessModeRead = isset (#const R_OK)
                   , accessModeWrite = isset (#const W_OK)
                   , accessModeExecute = isset (#const X_OK)
                   }
    where
      accessBits = (#const R_OK) .|. (#const W_OK) .|. (#const X_OK)
