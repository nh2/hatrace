{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}
#include <unistd.h>
#include <sys/stat.h>
#include <poll.h>
#include <sys/sysinfo.h>
#include <asm/prctl.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , GranularAccessMode(..)
  , fileExistence
  , StatStruct(..)
  , TimespecStruct(..)
  , PollFdStruct(..)
  , ArchPrctlSubfunction(..)
  , CIntRepresentable(..)
  , SysinfoStruct(..)
  ) where

import           Data.Bits
import           Data.List (intercalate)
import           Foreign.C.Types (CShort(..), CUShort(..), CInt(..), CUInt(..), CLong(..), CULong(..))
import           Foreign.Marshal.Array (peekArray, pokeArray)
import           Foreign.Ptr (plusPtr)
import           Foreign.Storable (Storable(..))
import           System.Hatrace.Format

-- | Helper type class for int-sized enum-like types
class CIntRepresentable a where
  toCInt :: a -> CInt
  fromCInt :: CInt -> a

class CShortRepresentable a where
  toCShort :: a -> CShort
  fromCShort :: CShort -> a

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

data PollFdStruct = PollFdStruct
  { fd      :: CInt
  , events  :: PollEvents
  , revents :: PollEvents
  } deriving (Eq, Ord, Show)

instance Storable PollFdStruct where
  sizeOf _ = #{size struct pollfd}
  alignment _ = #{alignment struct pollfd}
  peek p = do
    fd <- #{peek struct pollfd, fd} p
    events <- fromCShort <$> #{peek struct pollfd, events} p
    revents <- fromCShort <$> #{peek struct pollfd, revents} p
    return PollFdStruct{ fd = fd
                       , events = events
                       , revents = revents
                       }
  poke p PollFdStruct{..} = do
    #{poke struct pollfd, fd} p fd
    #{poke struct pollfd, events} p (toCShort events)
    #{poke struct pollfd, revents} p (toCShort revents)

instance ArgFormatting PollFdStruct where
  formatArg PollFdStruct {..} =
    StructArg [ ("fd", formatArg fd)
              , ("events", formatArg events)
              , ("revents", formatArg revents)
              ]

data PollEvents = PollEventsKnown GranularPollEvents
                | PollEventsUnknown CShort deriving (Eq, Ord, Show)

instance ArgFormatting PollEvents where
  formatArg = FixedStringArg . formatMode
    where
      formatMode (PollEventsKnown gpe) =
        let granularPollEvents =
              [ "POLLIN" | pollin gpe ] ++
              [ "POLLPRI" | pollpri gpe ] ++
              [ "POLLOUT" | pollout gpe ] ++
#ifdef __USE_GNU
              [ "POLLRDHUP" | pollrdhup gpe ] ++
#endif
              [ "POLLERR" | pollerr gpe ] ++
              [ "POLLHUP" | pollhup gpe ] ++
              [ "POLLNVAL" | pollnval gpe ] ++
#ifdef _XOPEN_SOURCE
              [ "POLLRDNORM" | pollrdnorm gpe ] ++
              [ "POLLRDBAND" | pollrdband gpe ] ++
              [ "POLLWRNORM" | pollwrnorm gpe ] ++
              [ "POLLWRBAND" | pollwrband gpe ] ++
#endif
              []
        in if null granularPollEvents then "0" else intercalate "|" granularPollEvents
      formatMode (PollEventsUnknown x) = show x

data GranularPollEvents = GranularPollEvents
  { pollin :: Bool
  , pollpri :: Bool
  , pollout :: Bool
#ifdef __USE_GNU
  , pollrdhup :: Bool
#endif
  , pollerr :: Bool
  , pollhup :: Bool
  , pollnval :: Bool
#ifdef _XOPEN_SOURCE
  , pollrdnorm :: Bool
  , pollrdband :: Bool
  , pollwrnorm :: Bool
  , pollwrband :: Bool
#endif
  } deriving (Eq, Ord, Show)

instance CShortRepresentable PollEvents where
  toCShort (PollEventsKnown gpe) = foldr (.|.) (fromIntegral (0 :: Int)) setBits
    where
      setBits =
        [ if pollin gpe then (#const POLLIN) else 0
        , if pollpri gpe then (#const POLLPRI) else 0
        , if pollout gpe then (#const POLLOUT) else 0
#ifdef __USE_GNU
        , if pollrdhup gpe then (#const POLLRDHUP) else 0
#endif
        , if pollerr gpe then (#const POLLERR) else 0
        , if pollhup gpe then (#const POLLHUP) else 0
        , if pollnval gpe then (#const POLLNVAL) else 0
#ifdef _XOPEN_SOURCE
        , if pollrdnorm gpe then (#const POLLRDNORM) else 0
        , if pollrdband gpe then (#const POLLRDBAND) else 0
        , if pollwrnorm gpe then (#const POLLWRNORM) else 0
        , if pollwrband gpe then (#const POLLWRBAND) else 0
#endif
        ]
  toCShort (PollEventsUnknown x) = x
  fromCShort m | (m .&. complement pollEventsBits) /= zeroBits = PollEventsUnknown m
               | otherwise =
                  let isset f = (m .&. f) /= zeroBits
                  in PollEventsKnown GranularPollEvents
                     { pollin = isset (#const POLLIN)
                     , pollpri = isset (#const POLLPRI)
                     , pollout = isset (#const POLLOUT)
#ifdef __USE_GNU
                     , pollrdhup = isset (#const POLLRDHUP)
#endif
                     , pollerr = isset (#const POLLERR)
                     , pollhup = isset (#const POLLHUP)
                     , pollnval = isset (#const POLLNVAL)
#ifdef _XOPEN_SOURCE
                     , pollrdnorm = isset (#const POLLRDNORM)
                     , pollrdband = isset (#const POLLRDBAND)
                     , pollwrnorm = isset (#const POLLWRNORM)
                     , pollwrband = isset (#const POLLWRBAND)
#endif
                     }
    where
      pollEventsBits = (#const POLLIN)
                     .|. (#const POLLPRI)
                     .|. (#const POLLOUT)
#ifdef __USE_GNU
                     .|. (#const POLLRDHUP)
#endif
                     .|. (#const POLLERR)
                     .|. (#const POLLHUP)
                     .|. (#const POLLNVAL)
#ifdef _XOPEN_SOURCE
                     .|. (#const POLLRDNORM)
                     .|. (#const POLLRDBAND)
                     .|. (#const POLLWRNORM)
                     .|. (#const POLLWRBAND)
#endif

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
