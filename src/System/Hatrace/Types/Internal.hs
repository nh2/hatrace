module System.Hatrace.Types.Internal
  ( CIntRepresentable(..)
  , hasSetBits
  ) where

import           Data.Bits
import           Foreign.C.Types (CInt(..))

-- | Helper type class for int-sized enum-like types
class CIntRepresentable a where
  toCInt :: a -> CInt
  fromCInt :: CInt -> a

hasSetBits :: CInt -> CInt -> Bool
hasSetBits value mask = (value .&. mask) == mask
