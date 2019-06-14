{-# LANGUAGE RecordWildCards #-}
#include <unistd.h>
#include <sys/stat.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , GranularAccessMode(..)
  , fileExistence
  , StatStruct(..)
  , TimespecStruct(..)
  , CIntRepresentable(..)
  ) where

import           Data.Bits
import           Data.List (intercalate)
import           Foreign.C.Types (CInt(..), CUInt(..), CLong(..), CULong(..))
import           Foreign.Storable (Storable(..))
import           System.Hatrace.Format

-- | Helper type class for int-sized enum-like types
class CIntRepresentable a where
  toCInt :: a -> CInt
  fromCInt :: CInt -> a

data FileAccessMode
  = FileAccessKnown GranularAccessMode
  | FileAccessUnknown CInt
  deriving (Eq, Ord, Show)

-- TODO think about special handling for bit flags so they could
-- be better represented in JSON for example
instance ArgFormatting FileAccessMode where
  formatArg = FixedArg . formatMode
    where
      formatMode (FileAccessKnown mode) =
        let granularModes = concat
              [ if accessModeRead mode then ["R_OK"] else []
              , if accessModeWrite mode then ["W_OK"] else []
              , if accessModeExecute mode then ["X_OK"] else []
              ]
        in if null granularModes then "F_OK" else intercalate "|" granularModes
      formatMode (FileAccessUnknown x) = show x

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

data StatStruct = StatStruct
  { st_dev :: CULong -- ^ ID of device containing file
  , st_ino :: CULong -- ^ Inode number
  , st_mode :: CUInt -- ^ File type and mode
  , st_nlink :: CULong -- ^ Number of hard links
  , st_uid :: CUInt -- ^ User ID of owner
  , st_gid :: CUInt -- ^ Group ID of owner
  , st_rdev :: CULong -- ^ Device ID (if special file)
  , st_size :: CLong -- ^ Total size, in bytes
  , st_blksize :: CLong -- ^ Block size for filesystem I/O
  , st_blocks :: CLong -- ^ Number of 512B blocks allocated
  , st_atim :: TimespecStruct -- ^ Time of last access
  , st_mtim :: TimespecStruct -- ^ Time of last modification
  , st_ctim :: TimespecStruct -- ^ Time of last status change
  } deriving (Eq, Ord, Show)

instance Storable StatStruct where
  sizeOf _ = #{size struct stat}
  alignment _ = #{alignment struct stat}
  peek p = do
    st_dev <- #{peek struct stat, st_dev} p
    st_ino <- #{peek struct stat, st_ino} p
    st_mode <- #{peek struct stat, st_mode} p
    st_nlink <- #{peek struct stat, st_nlink} p
    st_uid <- #{peek struct stat, st_uid} p
    st_gid <- #{peek struct stat, st_gid} p
    st_rdev <- #{peek struct stat, st_rdev} p
    st_size <- #{peek struct stat, st_size} p
    st_blksize <- #{peek struct stat, st_blksize} p
    st_blocks <- #{peek struct stat, st_blocks } p
    st_atim <- #{peek struct stat, st_atim} p
    st_mtim <- #{peek struct stat, st_mtim} p
    st_ctim <- #{peek struct stat, st_ctim} p
    return StatStruct{..}
  poke p StatStruct{..} = do
    #{poke struct stat, st_dev} p st_dev
    #{poke struct stat, st_ino} p st_ino
    #{poke struct stat, st_mode} p st_mode
    #{poke struct stat, st_nlink} p st_nlink
    #{poke struct stat, st_uid} p st_uid
    #{poke struct stat, st_gid} p st_gid
    #{poke struct stat, st_rdev} p st_rdev
    #{poke struct stat, st_size} p st_size
    #{poke struct stat, st_blksize} p st_blksize
    #{poke struct stat, st_blocks} p st_blocks
    #{poke struct stat, st_atim} p st_atim
    #{poke struct stat, st_mtim} p st_mtim
    #{poke struct stat, st_ctim} p st_ctim

-- outputtting st_mode and st_size first following strace
-- which appears to output only those
instance ArgFormatting StatStruct where
  formatArg StatStruct {..} =
    StructArg
      [ ("st_mode", formatArg st_mode)
      , ("st_size", formatArg st_size)
      , ("st_dev", formatArg st_dev)
      , ("st_ino", formatArg st_ino)
      , ("st_nlink", formatArg st_nlink)
      , ("st_uid", formatArg st_uid)
      , ("st_gid", formatArg st_gid)
      , ("st_rdev", formatArg st_rdev)
      , ("st_blksize", formatArg st_blksize)
      , ("st_blocks", formatArg st_blocks)
      , ("st_atim", formatArg st_atim)
      , ("st_mtim", formatArg st_mtim)
      , ("st_ctim", formatArg st_ctim)
      ]

data TimespecStruct = TimespecStruct
  { tv_sec :: CLong -- ^ Seconds
  , tv_nsec :: CLong -- ^ Nanoseconds
  } deriving (Eq, Ord, Show)

instance Storable TimespecStruct where
  sizeOf _ = #{size struct timespec}
  alignment _ = #{alignment struct timespec}
  peek p = do
    tv_sec <- #{peek struct timespec, tv_sec} p
    tv_nsec <- #{peek struct timespec, tv_nsec} p
    return TimespecStruct{..}
  poke p TimespecStruct{..} = do
    #{poke struct timespec, tv_sec} p tv_sec
    #{poke struct timespec, tv_nsec} p tv_nsec

instance ArgFormatting TimespecStruct where
  formatArg TimespecStruct {..} =
    StructArg [("tv_sec", formatArg tv_sec), ("tv_nsec", formatArg tv_nsec)]