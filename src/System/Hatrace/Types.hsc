{-# LANGUAGE RecordWildCards #-}
#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/sysinfo.h>
#include <asm/prctl.h>

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
  , ArchPrctlSubfunction(..)
  , CIntRepresentable(..)
  , SysinfoStruct(..)
  , AccessProtection(..)
  , GranularAccessProtection(..)
  , noAccess
  ) where

import           Data.Bits
import           Data.List (intercalate)
import           Foreign.C.Types (CUShort(..), CInt(..), CUInt(..), CLong(..), CULong(..))
import           Foreign.Marshal.Array (peekArray, pokeArray)
import           Foreign.Ptr (plusPtr)
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
  formatArg = FixedStringArg . formatMode
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

data MemoryProtectMode
  = MemoryProtectKnown GranularMemoryProtectMode
  | MemoryProtectUnknown CInt
  deriving (Eq, Ord, Show)

instance ArgFormatting MemoryProtectMode where
  formatArg = FixedStringArg . formatMode
    where
      formatMode (MemoryProtectKnown mode) =
        let granularModes = concat
              [ if protectModeExec  mode then ["PROT_EXEC"]  else []
              , if protectModeRead  mode then ["PROT_READ"]  else []
              , if protectModeWrite mode then ["PROT_WRITE"] else []
              , if protectModeNone  mode then ["PROT_NONE"]  else []
              ]
        in if null granularModes then "0" else intercalate "|" granularModes
      formatMode (MemoryProtectUnknown x) = show x

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

instance ArgFormatting MMapMode where
  formatArg = FixedStringArg . formatMode
    where
      formatMode (MMapModeKnown mode) =
        let granularModes = concat
              [ case mapSharing mode of
                  MMapShared -> ["MAP_SHARED"]
                  MMapPrivate -> ["MAP_PRIVATE"]
#ifdef MAP_SHARED_VALIDATE
                  MMapSharedValidate -> ["MAP_SHARED_VALIDATE"]
#endif
              , if map32Bit mode          then ["MAP_32BIT"]           else []
              , if mapAnonymous mode      then ["MAP_ANONYMOUS"]       else []
              , if mapDenyWrite mode      then ["MAP_DENYWRITE"]       else []
              , if mapExecutable mode     then ["MAP_EXECUTABLE"]      else []
              , if mapFixed mode          then ["MAP_FIXED"]           else []
#ifdef MAP_FIXED_NOREPLACE
              , if mapFixedNoreplace mode then ["MAP_FIXED_NOREPLACE"] else []
#endif
              , if mapGrowsdown mode      then ["MAP_GROWSDOWN"]       else []
              , if mapHugetlb mode        then ["MAP_HUGETLB"]         else []
#ifdef MAP_HUGE_2MB
              , if mapHuge2Mb mode        then ["MAP_HUGE_2MB"]        else []
#endif
#ifdef MAP_HUGE_1GB
              , if mapHuge1Gb mode        then ["MAP_HUGE_1GB"]        else []
#endif
              , if mapLocked mode         then ["MAP_LOCKED"]          else []
              , if mapNonblock mode       then ["MAP_NONBLOCK"]        else []
              , if mapNoReserve mode      then ["MAP_NORESERVE"]       else []
              , if mapPopulate mode       then ["MAP_POPULATE"]        else []
              , if mapStack mode          then ["MAP_STACK"]           else []
#ifdef MAP_SYNC
              , if mapSync mode           then ["MAP_SYNC"]            else []
#endif
#ifdef MAP_UNINITIALIZED
              , if mapUninitialized mode  then ["MAP_UNINITIALIZED"]   else []
#endif
              ]
        in if null granularModes then "0" else intercalate "|" granularModes
      formatMode (MMapModeUnknown x) = show x

data MMapSharing
  = MMapShared
  -- ^ Share this mapping.
  | MMapPrivate
  -- ^ Create a private copy-on-write mapping.
#ifdef MAP_SHARED_VALIDATE
  | MMapSharedValidate
  -- ^ This flag provides the same behavior as MAP_SHARED except that MMapShared
  -- mappings ignore unknown flags in flags. By contrast, when creating a mapping
  -- using MMapSharedValidate, the kernel verifies all passed flags are known and
  -- fails the mapping with the error EOPNOTSUPP for unknown flags. This mapping
  -- type is also required to be able to use some mapping flags (e.g., mapSync).
  -- (since Linux 4.15)
#endif
  deriving (Eq, Ord, Show)

-- | mmap mode, MAP_FILE and MAP_EXECUTABLE are ignored on Linux
data GranularMMapMode = GranularMMapMode
  { mapSharing :: MMapSharing
  , map32Bit :: Bool
  , mapAnonymous :: Bool
  , mapDenyWrite :: Bool
  , mapExecutable :: Bool
  , mapFixed :: Bool
#ifdef MAP_FIXED_NOREPLACE
  , mapFixedNoreplace :: Bool
    -- ^ since Linux 4.17
#endif
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
#ifdef MAP_SYNC
  , mapSync :: Bool
    -- ^ since Linux 4.15
#endif
#ifdef MAP_UNINITIALIZED
  , mapUninitialized :: Bool
#endif
  } deriving (Eq, Ord, Show)

instance CIntRepresentable MMapMode where
  toCInt (MMapModeKnown gp) = foldr (.|.) (fromIntegral (0 :: Int)) setBits
    where
      setBits =
        [ case mapSharing gp of
            MMapShared -> (#const MAP_SHARED)
            MMapPrivate -> (#const MAP_PRIVATE)
#ifdef MAP_SHARED_VALIDATE
            MMapSharedValidate -> (#const MAP_SHARED_VALIDATE)
#endif
        , if map32Bit gp          then (#const MAP_32BIT)           else 0
        , if mapAnonymous gp      then (#const MAP_ANONYMOUS)       else 0
        , if mapDenyWrite gp      then (#const MAP_DENYWRITE)       else 0
        , if mapExecutable gp     then (#const MAP_EXECUTABLE)      else 0
        , if mapFixed gp          then (#const MAP_FIXED)           else 0
#ifdef MAP_FIXED_NOREPLACE
        , if mapFixedNoreplace gp then (#const MAP_FIXED_NOREPLACE) else 0
#endif
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
#ifdef MAP_SYNC
        , if mapSync gp           then (#const MAP_SYNC)            else 0
#endif
#ifdef MAP_UNINITIALIZED
        , if mapUninitialized gp  then (#const MAP_UNINITIALIZED)   else 0
#endif
        ]
  toCInt (MMapModeUnknown x) = x
  fromCInt m | (m .&. complement mapBits) /= zeroBits = MMapModeUnknown m
             | otherwise =
                let isset f = (m .&. f) == f
                in MMapModeKnown GranularMMapMode
                   { mapSharing        =
#ifdef MAP_SHARED_VALIDATE
                       if isset (#const MAP_SHARED_VALIDATE)
                       then MMapSharedValidate
                       else
#endif
                         if isset (#const MAP_SHARED)
                         then MMapShared
                         else
                           if isset (#const MAP_PRIVATE)
                           then MMapPrivate
                           else error "Unexpected mmap sharing type"
                   , map32Bit          = isset (#const MAP_32BIT)
                   , mapAnonymous      = isset (#const MAP_ANONYMOUS)
                   , mapDenyWrite      = isset (#const MAP_DENYWRITE)
                   , mapExecutable     = isset (#const MAP_EXECUTABLE)
                   , mapFixed          = isset (#const MAP_FIXED)
#ifdef MAP_FIXED_NOREPLACE
                   , mapFixedNoreplace = isset (#const MAP_FIXED_NOREPLACE)
#endif
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
#ifdef MAP_SYNC
                   , mapSync           = isset (#const MAP_SYNC)
#endif
#ifdef MAP_UNINITIALIZED
                   , mapUninitialized  = isset (#const MAP_UNINITIALIZED)
#endif
                   }
    where
        mapBits = foldr (.|.) (fromIntegral (0 :: Int)) $
          [ #const MAP_SHARED
#ifdef MAP_SHARED_VALIDATE
          , #const MAP_SHARED_VALIDATE
#endif
          , #const MAP_PRIVATE
          , #const MAP_32BIT
          , #const MAP_ANON
          , #const MAP_ANONYMOUS
          , #const MAP_DENYWRITE
          , #const MAP_EXECUTABLE
          , #const MAP_FILE
          , #const MAP_FIXED
#ifdef MAP_FIXED_NOREPLACE
          , #const MAP_FIXED_NOREPLACE
#endif
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
#ifdef MAP_SYNC
          , #const MAP_SYNC
#endif
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

data ArchPrctlSubfunction
  = ArchSetFs
  | ArchGetFs
  | ArchSetGs
  | ArchGetGs
  | ArchUnknownSubfunction CInt
  deriving (Eq, Ord, Show)

instance CIntRepresentable ArchPrctlSubfunction where
  toCInt ArchSetFs = (#const ARCH_SET_FS)
  toCInt ArchGetFs = (#const ARCH_GET_FS)
  toCInt ArchSetGs = (#const ARCH_SET_GS)
  toCInt ArchGetGs = (#const ARCH_GET_GS)
  toCInt (ArchUnknownSubfunction unknown) = unknown
  fromCInt (#const ARCH_SET_FS) = ArchSetFs
  fromCInt (#const ARCH_GET_FS) = ArchGetFs
  fromCInt (#const ARCH_SET_GS) = ArchSetGs
  fromCInt (#const ARCH_GET_GS) = ArchGetGs
  fromCInt unknown = ArchUnknownSubfunction unknown

instance ArgFormatting ArchPrctlSubfunction where
  formatArg ArchSetFs = FixedStringArg "ARCH_SET_FS"
  formatArg ArchGetFs = FixedStringArg "ARCH_GET_FS"
  formatArg ArchSetGs = FixedStringArg "ARCH_SET_GS"
  formatArg ArchGetGs = FixedStringArg "ARCH_GET_GS"
  formatArg (ArchUnknownSubfunction unknown) =
    IntegerArg (fromIntegral unknown)

data SysinfoStruct = SysinfoStruct
  { uptime :: CLong -- ^ Seconds since boot
  , loads_1 :: CULong -- ^ 1 minute load average
  , loads_5 :: CULong -- ^ 5 minutes load average
  , loads_15 :: CULong -- ^ 15 minutes load average
  , totalram :: CULong -- ^ Total usable main memory size
  , freeram :: CULong -- ^ Available memory size
  , sharedram :: CULong -- ^ Amount of shared memory
  , bufferram :: CULong -- ^ Memory used by buffers
  , totalswap :: CULong -- ^ Total swap space size
  , freeswap :: CULong -- ^ Swap space still available
  , procs :: CUShort -- ^ Number of current processes
  , totalhigh :: CULong -- ^ Total high memory size
  , freehigh :: CULong -- ^ Available high memory size
  , mem_unit :: CUInt -- ^ Memory unit size in bytes
  } deriving (Eq, Ord, Show)

instance ArgFormatting SysinfoStruct where
  formatArg SysinfoStruct {..} =
    StructArg
      [ ("uptime", formatArg uptime)
      , ("loads", formatArg [loads_1, loads_5, loads_15])
      , ("totalram", formatArg totalram)
      , ("freeram", formatArg freeram)
      , ("sharedram", formatArg sharedram)
      , ("bufferram", formatArg bufferram)
      , ("totalswap", formatArg totalswap)
      , ("freeswap", formatArg freeswap)
      , ("procs", formatArg procs)
      , ("totalhigh", formatArg totalhigh)
      , ("freehigh", formatArg freehigh)
      , ("mem_unit", formatArg mem_unit)
      ]

instance Storable SysinfoStruct where
  sizeOf _ = #{size struct sysinfo}
  alignment _ = #{alignment struct sysinfo}
  peek p = do
    uptime <- #{peek struct sysinfo, uptime} p
    loads <- peekArray 3 (#{ptr struct sysinfo, loads} p)
    let [loads_1, loads_5, loads_15] = loads
    totalram <- #{peek struct sysinfo, totalram} p
    freeram <- #{peek struct sysinfo, freeram} p
    sharedram <- #{peek struct sysinfo, sharedram} p
    bufferram <- #{peek struct sysinfo, bufferram} p
    totalswap <- #{peek struct sysinfo, totalswap} p
    freeswap <- #{peek struct sysinfo, freeswap } p
    procs <- #{peek struct sysinfo, procs} p
    totalhigh <- #{peek struct sysinfo, totalhigh} p
    freehigh <- #{peek struct sysinfo, freehigh} p
    mem_unit <- #{peek struct sysinfo, mem_unit} p
    return SysinfoStruct{..}
  poke p SysinfoStruct{..} = do
    #{poke struct sysinfo, uptime} p uptime
    pokeArray (#{ptr struct sysinfo, loads} p) [loads_1, loads_5, loads_15]
    #{poke struct sysinfo, totalram} p totalram
    #{poke struct sysinfo, freeram} p freeram
    #{poke struct sysinfo, sharedram} p sharedram
    #{poke struct sysinfo, bufferram} p bufferram
    #{poke struct sysinfo, totalswap} p totalswap
    #{poke struct sysinfo, freeswap} p freeswap
    #{poke struct sysinfo, procs} p procs
    #{poke struct sysinfo, totalhigh} p totalhigh
    #{poke struct sysinfo, freehigh} p freehigh
    #{poke struct sysinfo, mem_unit} p mem_unit

data AccessProtection
  = AccessProtectionKnown GranularAccessProtection
  | AccessProtectionUnknown CInt
  deriving (Eq, Ord, Show)

-- | PROT_NONE designating no access at all is assumed when all of the
-- flag below get set to a false value, values PROT_SEM and PROT_SAO
-- appear to be architecture-specific and not available on X86-64
data GranularAccessProtection = GranularAccessProtection
  { accessProtectionRead :: Bool
  -- ^ PROT_READ  The memory can be read.
  , accessProtectionWrite :: Bool
  -- ^ PROT_WRITE The memory can be modified.
  , accessProtectionExec :: Bool
  -- ^ PROT_EXEC  The memory can be executed.
  , accessProtectionGrowsUp :: Bool
  -- ^ PROT_GROWSUP (since Linux 2.6.0) Apply the protection mode up to the end of
  -- a mapping that grows upwards.  (Such mappings are created for the stack area
  -- on architectures — for example, HP-PARISC — that have an upwardly growing stack.)
  , accessProtectionGrowsDown :: Bool
  -- ^ PROT_GROWSDOWN (since Linux 2.6.0) Apply the protection mode down to the
  -- beginning of a mapping that grows downward (which should be a stack  segment
  -- or a segment mapped with the MAP_GROWSDOWN flag set).
  } deriving (Eq, Ord, Show)

-- | special access protection not equal to any granular access flags
-- designating no access ata ll
noAccess :: GranularAccessProtection
noAccess = GranularAccessProtection False False False False False

instance ArgFormatting AccessProtection where
  formatArg = FixedStringArg . formatMode
    where
      formatMode (AccessProtectionKnown flags) =
        let granularFlags = concat
              [ if accessProtectionRead flags then ["PROT_READ"] else []
              , if accessProtectionWrite flags then ["PROT_WRITE"] else []
              , if accessProtectionExec flags then ["PROT_EXEC"] else []
              , if accessProtectionGrowsUp flags then ["PROT_GROWSUP"] else []
              , if accessProtectionGrowsDown flags then ["PROT_GROWSDOWN"] else []
              ]
        in if null granularFlags then "PROT_NONE" else intercalate "|" granularFlags
      formatMode (AccessProtectionUnknown x) = show x

instance CIntRepresentable AccessProtection where
  toCInt (AccessProtectionKnown ga) =
      r .|. w .|. x .|. up .|. down .|. (#const PROT_NONE)
    where
      r = if accessProtectionRead ga then (#const PROT_READ) else 0
      w = if accessProtectionWrite ga then (#const PROT_WRITE) else 0
      x = if accessProtectionExec ga then (#const PROT_EXEC) else 0
      up = if accessProtectionGrowsUp ga then (#const PROT_GROWSUP) else 0
      down = if accessProtectionGrowsDown ga then (#const PROT_GROWSDOWN) else 0
  toCInt (AccessProtectionUnknown x) = x
  fromCInt (#const PROT_NONE) = AccessProtectionKnown noAccess
  fromCInt m | (m .&. complement accessBits) /= zeroBits = AccessProtectionUnknown m
             | otherwise =
                let isset f = (m .&. f) /= zeroBits
                in AccessProtectionKnown GranularAccessProtection
                   { accessProtectionRead = isset (#const PROT_READ)
                   , accessProtectionWrite = isset (#const PROT_WRITE)
                   , accessProtectionExec = isset (#const PROT_EXEC)
                   , accessProtectionGrowsUp = isset (#const PROT_GROWSUP)
                   , accessProtectionGrowsDown = isset (#const PROT_GROWSDOWN)
                   }
    where
      accessBits =
        (#const PROT_NONE) .|. (#const PROT_READ) .|. (#const PROT_WRITE) .|.
        (#const PROT_EXEC) .|. (#const PROT_GROWSUP) .|. (#const PROT_GROWSDOWN)
