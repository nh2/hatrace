{-# LANGUAGE RecordWildCards #-}
#include <unistd.h>
#include <sys/stat.h>
#include <sys/mman.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , GranularAccessMode(..)
  , MemoryProtectMode(..)
  , GranularMemoryProtectMode(..)
  , MMapMode(..)
  , GranularMMapMode(..)
  , fileExistence
  , StatStruct(..)
  , TimespecStruct(..)
  , CIntRepresentable(..)
  , HatraceShow(..)
  ) where

import           Data.Bits
import           Data.List (intercalate)
import           Foreign.C.Types (CInt(..), CUInt(..), CLong(..), CULong(..))
import           Foreign.Storable (Storable(..))

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

data MemoryProtectMode
  = MemoryProtectKnown GranularMemoryProtectMode
  | MemoryProtectUnknown CInt
  deriving (Eq, Ord, Show)

instance HatraceShow MemoryProtectMode where
  hShow (MemoryProtectKnown mode) =
    let granularModes = concat 
          [ if protectModeExec  mode then ["PROT_EXEC"]  else []
          , if protectModeRead  mode then ["PROT_READ"]  else []
          , if protectModeWrite mode then ["PROT_WRITE"] else []
          , if protectModeNone  mode then ["PROT_NONE"]  else []
          ]
    in if null granularModes then "0" else intercalate "|" granularModes
  hShow (MemoryProtectUnknown x) = show x

data GranularMemoryProtectMode = GranularMemoryProtectMode
  { protectModeExec :: Bool
  , protectModeRead :: Bool
  , protectModeWrite :: Bool
  , protectModeNone :: Bool
  } deriving (Eq, Ord, Show)

instance CIntRepresentable MemoryProtectMode where
  toCInt (MemoryProtectKnown gp) = x .|. r .|. w .|. n
    where
      x = if protectModeExec gp then (#const PROT_EXEC)  else 0
      r = if protectModeExec gp then (#const PROT_READ)  else 0
      w = if protectModeExec gp then (#const PROT_WRITE) else 0
      n = if protectModeExec gp then (#const PROT_NONE)  else 0
  toCInt (MemoryProtectUnknown x) = x
  fromCInt m | (m .&. complement protectBits) /= zeroBits = MemoryProtectUnknown m
             | otherwise =
                let isset f = (m .&. f) /= zeroBits
                in MemoryProtectKnown GranularMemoryProtectMode
                   { protectModeExec  = isset (#const PROT_EXEC)
                   , protectModeRead  = isset (#const PROT_READ)
                   , protectModeWrite = isset (#const PROT_WRITE)
                   , protectModeNone  = isset (#const PROT_NONE)
                   }
    where
      protectBits = (#const PROT_EXEC) .|. (#const PROT_READ) .|. (#const PROT_WRITE) .|. (#const PROT_NONE)

data MMapMode
  = MMapModeKnown GranularMMapMode
  | MMapModeUnknown CInt
  deriving (Eq, Ord, Show)

instance HatraceShow MMapMode where
  hShow (MMapModeKnown mode) =
    let granularModes =
          [ "MAP_SHARED"          | mapShared mode ] ++
          [ "MAP_PRIVATE"         | mapPrivate mode ] ++
          [ "MAP_32BIT"           | map32Bit mode ] ++
          [ "MAP_ANON"            | mapAnon mode ] ++
          [ "MAP_ANONYMOUS"       | mapAnonymous mode ] ++
          [ "MAP_DENYWRITE"       | mapDenyWrite mode ] ++
          [ "MAP_EXECUTABLE"      | mapExecutable mode ] ++
          [ "MAP_FILE"            | mapFile mode ] ++
          [ "MAP_FIXED"           | mapFixed mode ] ++
#ifdef MAP_FIXED_NOREPLACE
          [ "MAP_FIXED_NOREPLACE" | mapFixedNoreplace mode ] ++
#endif
          [ "MAP_GROWSDOWN"       | mapGrowsdown mode ] ++
          [ "MAP_HUGETLB"         | mapHugetlb mode ] ++
#ifdef MAP_HUGE_2MB
          [ "MAP_HUGE_2MB"        | mapHuge2Mb mode ] ++
#endif
#ifdef MAP_HUGE_1GB
          [ "MAP_HUGE_1GB"        | mapHuge1Gb mode ] ++
#endif
          [ "MAP_LOCKED"          | mapLocked mode ] ++
          [ "MAP_NONBLOCK"        | mapNonblock mode ] ++
          [ "MAP_NORESERVE"       | mapNoReserve mode ] ++
          [ "MAP_POPULATE"        | mapPopulate mode ] ++
          [ "MAP_STACK"           | mapStack mode ] ++
#ifdef MAP_SYNC
          [ "MAP_SYNC"            | mapSync mode ] ++
#endif
#ifdef MAP_UNINITIALIZED
          [ "MAP_UNINITIALIZED"   | mapUninitialized mode ] ++
#endif
          []
    in if null granularModes then "0" else intercalate "|" granularModes
  hShow (MMapModeUnknown x) = show x

data GranularMMapMode = GranularMMapMode
  { mapShared :: Bool
  , mapPrivate :: Bool
  , map32Bit :: Bool
  , mapAnon :: Bool
  , mapAnonymous :: Bool
  , mapDenyWrite :: Bool
  , mapExecutable :: Bool
  , mapFile :: Bool
  , mapFixed :: Bool
  , mapFixedNoreplace :: Bool
  , mapGrowsdown :: Bool
  , mapHugetlb :: Bool
#ifdef MAP_HUGE_2MB
  , mapHuge2Mb :: Bool
#endif
#ifdef MAP_HUGE_1GB
  , mapHuge1Gb :: Bool
#endif
  , mapLocked :: Bool
  , mapNonblock :: Bool
  , mapNoReserve :: Bool
  , mapPopulate :: Bool
  , mapStack :: Bool
  , mapSync :: Bool
#ifdef MAP_UNINITIALIZED
  , mapUninitialized :: Bool
#endif
  } deriving (Eq, Ord, Show)

instance CIntRepresentable MMapMode where
  toCInt (MMapModeKnown gp) = foldr (.|.) (fromIntegral (0 :: Int)) setBits
    where
      setBits =
        [ if mapShared gp         then (#const MAP_SHARED)          else 0
        , if mapPrivate gp        then (#const MAP_PRIVATE)         else 0
        , if map32Bit gp          then (#const MAP_32BIT)           else 0
        , if mapAnon gp           then (#const MAP_ANON)            else 0
        , if mapAnonymous gp      then (#const MAP_ANONYMOUS)       else 0
        , if mapDenyWrite gp      then (#const MAP_DENYWRITE)       else 0
        , if mapExecutable gp     then (#const MAP_EXECUTABLE)      else 0
        , if mapFile gp           then (#const MAP_FILE)            else 0
        , if mapFixed gp          then (#const MAP_FIXED)           else 0
        , if mapFixedNoreplace gp then (#const MAP_FIXED_NOREPLACE) else 0
        , if mapGrowsdown gp      then (#const MAP_GROWSDOWN)       else 0
        , if mapHugetlb gp        then (#const MAP_HUGETLB)         else 0
#ifdef MAP_HUGE_2MB
        , if mapHuge2Mb gp        then (#const MAP_HUGE_2MB)        else 0
#endif
#ifdef MAP_HUGE_1GB
        , if mapHuge1Gb gp        then (#const MAP_HUGE_1GB)        else 0
#endif
        , if mapLocked gp         then (#const MAP_LOCKED)          else 0
        , if mapNonblock gp       then (#const MAP_NONBLOCK)        else 0
        , if mapNoReserve gp      then (#const MAP_NORESERVE)       else 0
        , if mapPopulate gp       then (#const MAP_POPULATE)        else 0
        , if mapStack gp          then (#const MAP_STACK)           else 0
        , if mapSync gp           then (#const MAP_SYNC)            else 0
#ifdef MAP_UNINITIALIZED
        , if mapUninitialized gp  then (#const MAP_UNINITIALIZED)   else 0
#endif
        ]
  toCInt (MMapModeUnknown x) = x
  fromCInt m | (m .&. complement mapBits) /= zeroBits = MMapModeUnknown m
             | otherwise =
                let isset f = (m .&. f) /= zeroBits
                in MMapModeKnown GranularMMapMode
                   { mapShared         = isset (#const MAP_SHARED)
                   , mapPrivate        = isset (#const MAP_PRIVATE)
                   , map32Bit          = isset (#const MAP_32BIT)
                   , mapAnon           = isset (#const MAP_ANON)
                   , mapAnonymous      = isset (#const MAP_ANONYMOUS)
                   , mapDenyWrite      = isset (#const MAP_DENYWRITE)
                   , mapExecutable     = isset (#const MAP_EXECUTABLE)
                   , mapFile           = isset (#const MAP_FILE)
                   , mapFixed          = isset (#const MAP_FIXED)
                   , mapFixedNoreplace = isset (#const MAP_FIXED_NOREPLACE)
                   , mapGrowsdown      = isset (#const MAP_GROWSDOWN)
                   , mapHugetlb        = isset (#const MAP_HUGETLB)
#ifdef MAP_HUGE_2MB
                   , mapHuge2Mb        = isset (#const MAP_HUGE_2MB)
#endif
#ifdef MAP_HUGE_1GB
                   , mapHuge1Gb        = isset (#const MAP_HUGE_1GB)
#endif
                   , mapLocked         = isset (#const MAP_LOCKED)
                   , mapNonblock       = isset (#const MAP_NONBLOCK)
                   , mapNoReserve      = isset (#const MAP_NORESERVE)
                   , mapPopulate       = isset (#const MAP_POPULATE)
                   , mapStack          = isset (#const MAP_STACK)
                   , mapSync           = isset (#const MAP_SYNC)
#ifdef MAP_UNINITIALIZED
                   , mapUninitialized  = isset (#const MAP_UNINITIALIZED)
#endif
                   }
    where
        mapBits = foldr (.|.) (fromIntegral (0 :: Int)) $
          [ #const MAP_SHARED
          , #const MAP_PRIVATE
          , #const MAP_32BIT
          , #const MAP_ANON
          , #const MAP_ANONYMOUS
          , #const MAP_DENYWRITE
          , #const MAP_EXECUTABLE
          , #const MAP_FILE
          , #const MAP_FIXED
          , #const MAP_FIXED_NOREPLACE
          , #const MAP_GROWSDOWN
          , #const MAP_HUGETLB
#ifdef MAP_HUGE_2MB
          , #const MAP_HUGE_2MB
#endif
#ifdef MAP_HUGE_1GB
          , #const MAP_HUGE_1GB
#endif
          , #const MAP_LOCKED
          , #const MAP_NONBLOCK
          , #const MAP_NORESERVE
          , #const MAP_POPULATE
          , #const MAP_STACK
          , #const MAP_SYNC
#ifdef MAP_UNINITIALIZED
          , #const MAP_UNINITIALIZED
#endif
          ]

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

-- | following strace output
instance HatraceShow StatStruct where
  hShow StatStruct{..} =
    "{s_mode=" ++ show st_mode ++ ", st_size=" ++ show st_size ++ ", ..}"

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
