{-# LANGUAGE RecordWildCards #-}
{-# LANGUAGE ScopedTypeVariables #-}

-- To use `POLLRDHUP` with glibc, `_GNU_SOURCE` must be defined
-- before any header file imports; see `man 2 poll`.
#ifdef USE_POLL_POLLRDHUP
#define _GNU_SOURCE
#endif

#include <unistd.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/sysinfo.h>
#include <asm/prctl.h>
#include <poll.h>
#include <signal.h>

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
  , PollFdStruct(..)
  , PollEvents(..)
  , GranularPollEvents(..)
  , CIntRepresentable(..)
  , SysinfoStruct(..)
  , AccessProtection(..)
  , GranularAccessProtection(..)
  , noAccess
  , SigSet(..)
  , AddressFamily(..)
  , ConcreteAddressFamily(..)
  , SocketType(..)
  , SocketDetails(..)
  , ShutdownHow(..)
  , SendFlags(..)
  , GranularSendFlags(..)
  , ReceiveFlags(..)
  , GranularReceiveFlags(..)
  , MemAdvice(..)
  , MadvBehavior(..)
  ) where

import           Control.Monad (filterM)
import           Data.Bits
import           Data.List (intercalate)
import           Data.Map (lookup)
import           Data.Maybe (catMaybes)
import           Foreign.C.Types (CShort(..), CUShort(..), CInt(..), CUInt(..), CLong(..), CULong(..))
import           Foreign.Marshal (copyBytes)
import           Foreign.Marshal.Array (peekArray, pokeArray)
import           Foreign.Ptr (plusPtr, castPtr)
import           Foreign.ForeignPtr (withForeignPtr, newForeignPtr_)
import           Foreign.Storable (Storable(..))
import qualified System.Posix.Signals as Signals hiding (inSignalSet)
import           System.Hatrace.Signals
import           System.Hatrace.Types.Internal
import           System.Hatrace.Format


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

-- | We assume F_OK being equal to 0 (which it normally is)
$(deriveCIntRepresentable ''FileAccessMode
  [ ('accessModeRead, (#const R_OK))
  , ('accessModeWrite, (#const W_OK))
  , ('accessModeExecute, (#const X_OK))
  ])

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
              [ case mapType mode of
                  MMapShared -> ["MAP_SHARED"]
                  MMapPrivate -> ["MAP_PRIVATE"]
#ifdef MAP_SHARED_VALIDATE
                  MMapSharedValidate -> ["MAP_SHARED_VALIDATE"]
#endif
                  MMapTypeUnknown x -> [show x]
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

-- | https://github.com/torvalds/linux/blob/master/include/uapi/asm-generic/mman-common.h
-- defines MAP_TYPE as 0x0f so in theory there could be up to 15 types but please keep
-- in mind that it's Linux-specific
data MMapType
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
  | MMapTypeUnknown CUShort
  deriving (Eq, Ord, Show)

-- | mmap mode, MAP_FILE and MAP_EXECUTABLE are ignored on Linux
data GranularMMapMode = GranularMMapMode
  { mapType :: MMapType
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
  toCInt (MMapModeKnown gp) = foldr (.|.) typeBits setBits
    where
      typeBits = fromIntegral $ case mapType gp of
            MMapShared -> (#const MAP_SHARED)
            MMapPrivate -> (#const MAP_PRIVATE)
#ifdef MAP_SHARED_VALIDATE
            MMapSharedValidate -> (#const MAP_SHARED_VALIDATE)
#endif
            MMapTypeUnknown x -> x
      setBits =
        [ if map32Bit gp          then (#const MAP_32BIT)           else 0
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
                   { mapType           =
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

data AddressFamily
  = AddressFamilyKnown ConcreteAddressFamily
  | AddressFamilyUnknown CInt
  deriving (Eq, Ord, Show)

data ConcreteAddressFamily
  = AddressFamilyUnspecified
  | AddressFamilyUnix
  | AddressFamilyInet
  | AddressFamilyAX25
  | AddressFamilyIPX
  | AddressFamilyAppleTalk
  | AddressFamilyNETROM
  | AddressFamilyBridge
  | AddressFamilyATMPVC
  | AddressFamilyX25
  | AddressFamilyInet6
  | AddressFamilyROSE
  | AddressFamilyDECnet
  | AddressFamilyNETBEUI
  | AddressFamilySecurity
  | AddressFamilyKey
  | AddressFamilyNetlink
  | AddressFamilyPacket
  | AddressFamilyAsh
  | AddressFamilyEConet
  | AddressFamilyATMSVC
  | AddressFamilyRDS
  | AddressFamilySNA
  | AddressFamilyIRDA
  | AddressFamilyPPPoX
  | AddressFamilywanpipe
  | AddressFamilyLLC
#ifdef AF_IB
  | AddressFamilyIB
#endif
#ifdef AF_MPLS
  | AddressFamilyMPLS
#endif
  | AddressFamilyCAN
  | AddressFamilyTIPC
  | AddressFamilyBluetooth
  | AddressFamilyIUCV
  | AddressFamilyRxRPC
  | AddressFamilyISDN
  | AddressFamilyPhonet
  | AddressFamilyIEEE802154
  | AddressFamilyCAIF
  | AddressFamilyAlg
  | AddressFamilyNFC
  | AddressFamilyVSock
#ifdef AF_KCM
  | AddressFamilyKCM
#endif
#ifdef AF_QIPCRTR
  | AddressFamilyQIPCRTR
#endif
#ifdef AF_SMC
  | AddressFamilySMC
#endif
#ifdef AF_XDP
  | AddressFamilyXDP
#endif
  deriving (Eq, Ord, Show)

instance CIntRepresentable AddressFamily where
  toCInt (AddressFamilyKnown family) =
    case family of
      AddressFamilyUnspecified -> (#const AF_UNSPEC)
      AddressFamilyUnix -> (#const AF_UNIX)
      AddressFamilyInet -> (#const AF_INET)
      AddressFamilyAX25 -> (#const AF_AX25)
      AddressFamilyIPX -> (#const AF_IPX)
      AddressFamilyAppleTalk -> (#const AF_APPLETALK)
      AddressFamilyNETROM -> (#const AF_NETROM)
      AddressFamilyBridge -> (#const AF_BRIDGE)
      AddressFamilyATMPVC -> (#const AF_ATMPVC)
      AddressFamilyX25 -> (#const AF_X25)
      AddressFamilyInet6 -> (#const AF_INET6)
      AddressFamilyROSE -> (#const AF_ROSE)
      AddressFamilyDECnet -> (#const AF_DECnet)
      AddressFamilyNETBEUI -> (#const AF_NETBEUI)
      AddressFamilySecurity -> (#const AF_SECURITY)
      AddressFamilyKey -> (#const AF_KEY)
      AddressFamilyNetlink -> (#const AF_NETLINK)
      AddressFamilyPacket -> (#const AF_PACKET)
      AddressFamilyAsh -> (#const AF_ASH)
      AddressFamilyEConet -> (#const AF_ECONET)
      AddressFamilyATMSVC -> (#const AF_ATMSVC)
      AddressFamilyRDS -> (#const AF_RDS)
      AddressFamilySNA -> (#const AF_SNA)
      AddressFamilyIRDA -> (#const AF_IRDA)
      AddressFamilyPPPoX -> (#const AF_PPPOX)
      AddressFamilywanpipe -> (#const AF_WANPIPE)
      AddressFamilyLLC -> (#const AF_LLC)
#ifdef AF_IB
      AddressFamilyIB -> (#const AF_IB)
#endif
#ifdef AF_MPLS
      AddressFamilyMPLS -> (#const AF_MPLS)
#endif
      AddressFamilyCAN -> (#const AF_CAN)
      AddressFamilyTIPC -> (#const AF_TIPC)
      AddressFamilyBluetooth -> (#const AF_BLUETOOTH)
      AddressFamilyIUCV -> (#const AF_IUCV)
      AddressFamilyRxRPC -> (#const AF_RXRPC)
      AddressFamilyISDN -> (#const AF_ISDN)
      AddressFamilyPhonet -> (#const AF_PHONET)
      AddressFamilyIEEE802154 -> (#const AF_IEEE802154)
      AddressFamilyCAIF -> (#const AF_CAIF)
      AddressFamilyAlg -> (#const AF_ALG)
      AddressFamilyNFC -> (#const AF_NFC)
      AddressFamilyVSock -> (#const AF_VSOCK)
#ifdef AF_KCM
      AddressFamilyKCM -> (#const AF_KCM)
#endif
#ifdef AF_QIPCRTR
      AddressFamilyQIPCRTR -> (#const AF_QIPCRTR)
#endif
#ifdef AF_SMC
      AddressFamilySMC -> (#const AF_SMC)
#endif
#ifdef AF_XDP
      AddressFamilyXDP -> (#const AF_XDP)
#endif
  toCInt (AddressFamilyUnknown unknown) = unknown
  fromCInt af = case af of
      (#const AF_UNSPEC) -> AddressFamilyKnown AddressFamilyUnspecified
      (#const AF_UNIX) -> AddressFamilyKnown AddressFamilyUnix
      (#const AF_INET) -> AddressFamilyKnown AddressFamilyInet
      (#const AF_AX25) -> AddressFamilyKnown AddressFamilyAX25
      (#const AF_IPX) -> AddressFamilyKnown AddressFamilyIPX
      (#const AF_APPLETALK) -> AddressFamilyKnown AddressFamilyAppleTalk
      (#const AF_NETROM) -> AddressFamilyKnown AddressFamilyNETROM
      (#const AF_BRIDGE) -> AddressFamilyKnown AddressFamilyBridge
      (#const AF_ATMPVC) -> AddressFamilyKnown AddressFamilyATMPVC
      (#const AF_X25) -> AddressFamilyKnown AddressFamilyX25
      (#const AF_INET6) -> AddressFamilyKnown AddressFamilyInet6
      (#const AF_ROSE) -> AddressFamilyKnown AddressFamilyROSE
      (#const AF_DECnet) -> AddressFamilyKnown AddressFamilyDECnet
      (#const AF_NETBEUI) -> AddressFamilyKnown AddressFamilyNETBEUI
      (#const AF_SECURITY) -> AddressFamilyKnown AddressFamilySecurity
      (#const AF_KEY) -> AddressFamilyKnown AddressFamilyKey
      (#const AF_NETLINK) -> AddressFamilyKnown AddressFamilyNetlink
      (#const AF_PACKET) -> AddressFamilyKnown AddressFamilyPacket
      (#const AF_ASH) -> AddressFamilyKnown AddressFamilyAsh
      (#const AF_ECONET) -> AddressFamilyKnown AddressFamilyEConet
      (#const AF_ATMSVC) -> AddressFamilyKnown AddressFamilyATMSVC
      (#const AF_RDS) -> AddressFamilyKnown AddressFamilyRDS
      (#const AF_SNA) -> AddressFamilyKnown AddressFamilySNA
      (#const AF_IRDA) -> AddressFamilyKnown AddressFamilyIRDA
      (#const AF_PPPOX) -> AddressFamilyKnown AddressFamilyPPPoX
      (#const AF_WANPIPE) -> AddressFamilyKnown AddressFamilywanpipe
      (#const AF_LLC) -> AddressFamilyKnown AddressFamilyLLC
#ifdef AF_IB
      (#const AF_IB) -> AddressFamilyKnown AddressFamilyIB
#endif
#ifdef AF_MPLS
      (#const AF_MPLS) -> AddressFamilyKnown AddressFamilyMPLS
#endif
      (#const AF_CAN) -> AddressFamilyKnown AddressFamilyCAN
      (#const AF_TIPC) -> AddressFamilyKnown AddressFamilyTIPC
      (#const AF_BLUETOOTH) -> AddressFamilyKnown AddressFamilyBluetooth
      (#const AF_IUCV) -> AddressFamilyKnown AddressFamilyIUCV
      (#const AF_RXRPC) -> AddressFamilyKnown AddressFamilyRxRPC
      (#const AF_ISDN) -> AddressFamilyKnown AddressFamilyISDN
      (#const AF_PHONET) -> AddressFamilyKnown AddressFamilyPhonet
      (#const AF_IEEE802154) -> AddressFamilyKnown AddressFamilyIEEE802154
      (#const AF_CAIF) -> AddressFamilyKnown AddressFamilyCAIF
      (#const AF_ALG) -> AddressFamilyKnown AddressFamilyAlg
      (#const AF_NFC) -> AddressFamilyKnown AddressFamilyNFC
      (#const AF_VSOCK) -> AddressFamilyKnown AddressFamilyVSock
#ifdef AF_KCM
      (#const AF_KCM) -> AddressFamilyKnown AddressFamilyKCM
#endif
#ifdef AF_QIPCRTR
      (#const AF_QIPCRTR) -> AddressFamilyKnown AddressFamilyQIPCRTR
#endif
#ifdef AF_SMC
      (#const AF_SMC) -> AddressFamilyKnown AddressFamilySMC
#endif
#ifdef AF_XDP
      (#const AF_XDP) -> AddressFamilyKnown AddressFamilyXDP
#endif
      unknown -> AddressFamilyUnknown unknown

instance ArgFormatting AddressFamily where
  formatArg (AddressFamilyKnown family) =
    FixedStringArg $ case family of
      AddressFamilyUnspecified -> "AF_UNSPEC"
      AddressFamilyUnix -> "AF_UNIX"
      AddressFamilyInet -> "AF_INET"
      AddressFamilyAX25 -> "AF_AX25"
      AddressFamilyIPX -> "AF_IPX"
      AddressFamilyAppleTalk -> "AF_APPLETALK"
      AddressFamilyNETROM -> "AF_NETROM"
      AddressFamilyBridge -> "AF_BRIDGE"
      AddressFamilyATMPVC -> "AF_ATMPVC"
      AddressFamilyX25 -> "AF_X25"
      AddressFamilyInet6 -> "AF_INET6"
      AddressFamilyROSE -> "AF_ROSE"
      AddressFamilyDECnet -> "AF_ROSE"
      AddressFamilyNETBEUI -> "AF_NETBEUI"
      AddressFamilySecurity -> "AF_SECURITY"
      AddressFamilyKey -> "AF_KEY"
      AddressFamilyNetlink -> "AF_NETLINK"
      AddressFamilyPacket -> "AF_PACKET"
      AddressFamilyAsh -> "AF_ASH"
      AddressFamilyEConet -> "AF_ECONET"
      AddressFamilyATMSVC -> "AF_ATMSVC"
      AddressFamilyRDS -> "AF_RDS"
      AddressFamilySNA -> "AF_SNA"
      AddressFamilyIRDA -> "AF_IRDA"
      AddressFamilyPPPoX -> "AF_PPPOX"
      AddressFamilywanpipe -> "AF_WANPIPE"
      AddressFamilyLLC -> "AF_LLC"
#ifdef AF_IB
      AddressFamilyIB -> "AF_IB"
#endif
#ifdef AF_MPLS
      AddressFamilyMPLS -> "AF_MPLS"
#endif
      AddressFamilyCAN -> "AF_CAN"
      AddressFamilyTIPC -> "AF_TIPC"
      AddressFamilyBluetooth -> "AF_BLUETOOTH"
      AddressFamilyIUCV -> "AF_IUCV"
      AddressFamilyRxRPC -> "AF_RXRPC"
      AddressFamilyISDN -> "AF_ISDN"
      AddressFamilyPhonet -> "AF_PHONET"
      AddressFamilyIEEE802154 -> "AF_IEEE802154"
      AddressFamilyCAIF -> "AF_CAIF"
      AddressFamilyAlg -> "AF_ALG"
      AddressFamilyNFC -> "AF_NFC"
      AddressFamilyVSock -> "AF_VSOCK"
#ifdef AF_KCM
      AddressFamilyKCM -> "AF_KCM"
#endif
#ifdef AF_QIPCRTR
      AddressFamilyQIPCRTR -> "AF_QIPCRTR"
#endif
#ifdef AF_SMC
      AddressFamilySMC -> "AF_SMC"
#endif
#ifdef AF_XDP
      AddressFamilyXDP -> "AF_XDP"
#endif
  formatArg (AddressFamilyUnknown unknown) =
    IntegerArg (fromIntegral unknown)

data SocketType
  = SocketTypeKnown SocketDetails
  | SocketTypeUnknown CInt
  deriving (Eq, Ord, Show)

data SocketDetails =
  SocketDetails
    { sdType :: BaseSocketType
    , sdNonBlock :: Bool
    , sdCloExec :: Bool
    }
  deriving (Eq, Ord, Show)

data BaseSocketType
  = SocketStream
  | SocketDgram
  | SocketSeqPacket
  | SocketRaw
  | SocketRDM
  | SocketPacket
  deriving (Eq, Ord, Show)

instance CIntRepresentable SocketType where
  toCInt (SocketTypeKnown details) = baseType .|. nonBlock .|. cloExec
    where
      baseType = case sdType details of
        SocketStream -> (#const SOCK_STREAM)
        SocketDgram -> (#const SOCK_DGRAM)
        SocketSeqPacket -> (#const SOCK_SEQPACKET)
        SocketRaw -> (#const SOCK_RAW)
        SocketRDM -> (#const SOCK_RDM)
        SocketPacket -> (#const SOCK_PACKET)
      nonBlock = if sdNonBlock details then (#const SOCK_NONBLOCK) else 0
      cloExec = if sdCloExec details then (#const SOCK_CLOEXEC) else 0
  toCInt (SocketTypeUnknown unknown) = unknown
  fromCInt s
    | s `hasSetBits` (#const SOCK_STREAM) = socketOfType SocketStream
    | s `hasSetBits` (#const SOCK_DGRAM) = socketOfType SocketDgram
    | s `hasSetBits` (#const SOCK_SEQPACKET) = socketOfType SocketSeqPacket
    | s `hasSetBits` (#const SOCK_RAW) = socketOfType SocketRaw
    | s `hasSetBits` (#const SOCK_RDM) = socketOfType SocketRDM
    | s `hasSetBits` (#const SOCK_PACKET) = socketOfType SocketPacket
    | otherwise = SocketTypeUnknown s
    where
      socketOfType t = SocketTypeKnown $ SocketDetails t nonBlock cloExec
      nonBlock = s `hasSetBits` (#const SOCK_NONBLOCK)
      cloExec = s `hasSetBits` (#const SOCK_CLOEXEC)

instance ArgFormatting SocketType where
  formatArg (SocketTypeUnknown unknown) = IntegerArg (fromIntegral unknown)
  formatArg (SocketTypeKnown SocketDetails{..}) =
    FixedStringArg $ intercalate "|" (baseTypeStr ++ nonBlock ++ cloExec)
    where
      baseTypeStr = case sdType of
          SocketStream -> ["SOCK_STREAM"]
          SocketDgram -> ["SOCK_DGRAM"]
          SocketSeqPacket -> ["SOCK_SEQPACKET"]
          SocketRaw -> ["SOCK_RAW"]
          SocketRDM -> ["SOCK_RDM"]
          SocketPacket -> ["SOCK_PACKET"]
      nonBlock = if sdNonBlock then ["SOCK_NONBLOCK"] else []
      cloExec = if sdCloExec then ["SOCK_CLOEXEC"] else []

data ShutdownHow = ShutdownHowKnown DisallowConnections
  | ShutdownHowUnknown CInt
  deriving (Eq, Ord, Show)

data DisallowConnections
  = ReceptionsDisallowed
  | TransmissionsDisallowed
  | BothDisallowed
  deriving (Eq, Ord, Show)

instance CIntRepresentable ShutdownHow where
  toCInt (ShutdownHowKnown how) =
    case how of
      ReceptionsDisallowed -> (#const SHUT_RD)
      TransmissionsDisallowed -> (#const SHUT_WR)
      BothDisallowed -> (#const SHUT_RDWR)
  toCInt (ShutdownHowUnknown unknown) = unknown
  fromCInt h = case h of
    (#const SHUT_RD) -> ShutdownHowKnown ReceptionsDisallowed
    (#const SHUT_WR) -> ShutdownHowKnown TransmissionsDisallowed
    (#const SHUT_RDWR) -> ShutdownHowKnown BothDisallowed
    unknown -> ShutdownHowUnknown unknown

instance ArgFormatting ShutdownHow where
  formatArg (ShutdownHowUnknown unknown) = IntegerArg (fromIntegral unknown)
  formatArg (ShutdownHowKnown t) = FixedStringArg $ case t of
    ReceptionsDisallowed -> "SHUT_RD"
    TransmissionsDisallowed -> "SHUT_WR"
    BothDisallowed ->  "SHUT_RDWR"

data SendFlags
  = SendFlagsKnown GranularSendFlags
  | SendFlagsUnknown CInt
  deriving (Eq, Ord, Show)

data GranularSendFlags = GranularSendFlags
  { sendMsgOOB :: Bool
  , sendMsgDontRoute :: Bool
  , sendMsgDontWait :: Bool
  , sendMsgEOR :: Bool
  , sendMsgConfirm :: Bool
  , sendMsgNoSignal :: Bool
  , sendMsgMore :: Bool
  } deriving (Eq, Ord, Show)

instance ArgFormatting SendFlags where
  formatArg (SendFlagsKnown flags) =
    let flagValues = concat
          [ if sendMsgOOB flags then ["MSG_OOB"] else []
          , if sendMsgDontRoute flags then ["MSG_DONTROUTE"] else []
          , if sendMsgDontWait flags then ["MSG_DONTWAIT"] else []
          , if sendMsgEOR flags then ["MSG_EOR"] else []
          , if sendMsgConfirm flags then ["MSG_CONFIRM"] else []
          , if sendMsgNoSignal flags then ["MSG_NOSIGNAL"] else []
          , if sendMsgMore flags then ["MSG_MORE"] else []
          ]
    in if null flagValues then IntegerArg 0 else FixedStringArg (intercalate "|" flagValues)
  formatArg (SendFlagsUnknown unknown) = IntegerArg (fromIntegral unknown)

instance CIntRepresentable SendFlags where
  toCInt (SendFlagsKnown flags) =
    let readFlag field flag = if field flags then flag else 0
        allFlags =
          [ (sendMsgOOB, (#const MSG_OOB))
          , (sendMsgDontRoute, (#const MSG_DONTROUTE))
          , (sendMsgDontWait, (#const MSG_DONTWAIT))
          , (sendMsgEOR, (#const MSG_EOR))
          , (sendMsgConfirm, (#const MSG_CONFIRM))
          , (sendMsgNoSignal, (#const MSG_NOSIGNAL))
          , (sendMsgMore, (#const MSG_MORE))
          ]
    in foldr (.|.) zeroBits $ map (uncurry readFlag) allFlags
  toCInt (SendFlagsUnknown unknown) = unknown
  fromCInt flags =
    let isset f = flags `hasSetBits` f
        allBitsKnown = foldr (.|.) zeroBits bitsKnown
        bitsKnown =
          [ (#const MSG_OOB)
          , (#const MSG_DONTROUTE)
          , (#const MSG_DONTWAIT)
          , (#const MSG_EOR)
          , (#const MSG_CONFIRM)
          , (#const MSG_NOSIGNAL)
          , (#const MSG_MORE)
          ]
        onlyKnown = flags .&. complement allBitsKnown /= zeroBits
    in if onlyKnown
       then SendFlagsKnown $
            GranularSendFlags
            { sendMsgOOB = isset (#const MSG_OOB)
            , sendMsgDontRoute = isset (#const MSG_DONTROUTE)
            , sendMsgDontWait = isset (#const MSG_DONTWAIT)
            , sendMsgEOR = isset (#const MSG_EOR)
            , sendMsgConfirm = isset (#const MSG_CONFIRM)
            , sendMsgNoSignal = isset (#const MSG_NOSIGNAL)
            , sendMsgMore = isset (#const MSG_MORE)
            }
       else SendFlagsUnknown flags

data ReceiveFlags
  = ReceiveFlagsKnown GranularReceiveFlags
  | ReceiveFlagsUnknown CInt
  deriving (Eq, Ord, Show)

data GranularReceiveFlags = GranularReceiveFlags
  { recvMsgCmsgCloExec :: Bool
  , recvMsgDontWait :: Bool
  , recvMsgErrQueue :: Bool
  , recvMsgOOB :: Bool
  , recvMsgPeek :: Bool
  , recvMsgTrunc :: Bool
  , recvMsgWaitAll :: Bool
  } deriving (Eq, Ord, Show)

instance ArgFormatting ReceiveFlags where
  formatArg (ReceiveFlagsKnown flags) =
    let flagValues = concat
          [ if recvMsgCmsgCloExec flags then ["MSG_CMSG_CLOEXEC"] else []
          , if recvMsgDontWait flags then ["MSG_DONTWAIT"] else []
          , if recvMsgErrQueue flags then ["MSG_ERRQUEUE"] else []
          , if recvMsgOOB flags then ["MSG_OOB"] else []
          , if recvMsgPeek flags then ["MSG_PEEK"] else []
          , if recvMsgTrunc flags then ["MSG_TRUNC"] else []
          , if recvMsgWaitAll flags then ["MSG_WAITALL"] else []
          ]
    in if null flagValues then IntegerArg 0 else FixedStringArg (intercalate "|" flagValues)
  formatArg (ReceiveFlagsUnknown unknown) = IntegerArg (fromIntegral unknown)

instance CIntRepresentable ReceiveFlags where
  toCInt (ReceiveFlagsKnown flags) =
    let readFlag field flag = if field flags then flag else 0
        allFlags =
          [ (recvMsgCmsgCloExec, (#const MSG_CMSG_CLOEXEC))
          , (recvMsgDontWait, (#const MSG_DONTWAIT))
          , (recvMsgErrQueue, (#const MSG_ERRQUEUE))
          , (recvMsgOOB, (#const MSG_OOB))
          , (recvMsgPeek, (#const MSG_PEEK))
          , (recvMsgTrunc, (#const MSG_TRUNC))
          , (recvMsgWaitAll, (#const MSG_WAITALL))
          ]
    in foldr (.|.) zeroBits $ map (uncurry readFlag) allFlags
  toCInt (ReceiveFlagsUnknown unknown) = unknown
  fromCInt flags =
    let isset f = flags `hasSetBits` f
        allBitsKnown = foldr (.|.) zeroBits bitsKnown
        bitsKnown =
          [ (#const MSG_CMSG_CLOEXEC)
          , (#const MSG_DONTROUTE)
          , (#const MSG_ERRQUEUE)
          , (#const MSG_OOB)
          , (#const MSG_PEEK)
          , (#const MSG_TRUNC)
          , (#const MSG_WAITALL)
          ]
        onlyKnown = flags .&. complement allBitsKnown /= zeroBits
    in if onlyKnown
       then ReceiveFlagsKnown $
            GranularReceiveFlags
            { recvMsgCmsgCloExec = isset (#const MSG_CMSG_CLOEXEC)
            , recvMsgDontWait = isset (#const MSG_DONTWAIT)
            , recvMsgErrQueue = isset (#const MSG_ERRQUEUE)
            , recvMsgOOB = isset (#const MSG_OOB)
            , recvMsgPeek = isset (#const MSG_PEEK)
            , recvMsgTrunc = isset (#const MSG_TRUNC)
            , recvMsgWaitAll = isset (#const MSG_WAITALL)
            }
       else ReceiveFlagsUnknown flags

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
#ifdef USE_POLL_POLLRDHUP
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

-- |Only explicitly defined in man pages poll bits are currently used.
data GranularPollEvents = GranularPollEvents
  { pollin :: Bool
  , pollpri :: Bool
  , pollout :: Bool
#ifdef USE_POLL_POLLRDHUP
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
#ifdef USE_POLL_POLLRDHUP
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
#ifdef USE_POLL_POLLRDHUP
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
#ifdef USE_POLL_POLLRDHUP
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

$(deriveArgFormatting ''AccessProtection "PROT_NONE"
  [ ('accessProtectionRead, "PROT_READ")
  , ('accessProtectionWrite, "PROT_WRITE")
  , ('accessProtectionExec, "PROT_EXEC")
  , ('accessProtectionGrowsUp, "PROT_GROWSUP")
  , ('accessProtectionGrowsDown, "PROT_GROWSDOWN")
  ])

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

newtype SigSet
  = SigSet [Signals.Signal]
  deriving (Eq, Ord, Show)

instance Storable SigSet where
  sizeOf _ = sizeOfCSigset
  alignment _ = alignment (undefined :: CULong)
  peek p = do
    sigsetPtr <- newForeignPtr_ $ castPtr p
    SigSet <$> filterM (flip inSignalSet sigsetPtr) allSignals
  poke ptr (SigSet signals) = do
    let targetPtr = castPtr ptr
    tempSetPtr <- emptySignalSet
    mapM_ (flip addSignal tempSetPtr) signals
    withForeignPtr tempSetPtr $ \p -> copyBytes targetPtr p sizeOfCSigset

instance ArgFormatting SigSet where
  formatArg (SigSet signals) =
    ListArg $ catMaybes $ map signalToStringArg signals
    where
      signalToStringArg =
        fmap (FixedStringArg . snd) . flip Data.Map.lookup signalMap

data MemAdvice
  = MemAdviceKnown MadvBehavior
  | MemAdviceUnknown CInt
  deriving (Eq, Ord, Show)

-- | from @include/uapi/asm-generic/mman-common.h@ in kernel sources
data MadvBehavior
  = MadvNormal
  | MadvRandom
  | MadvSequential
  | MadvWillNeed
  | MadvDontNeed
  | MadvFree
  | MadvRemove
  | MadvDontFork
  | MadvDoFork
  | MadvHWPoison
#ifdef MADV_SOFT_OFFLINE
  | MadvSoftOffline
#endif
  | MadvMergeable
  | MadvUnmergeable
  | MadvHugePage
  | MadvNoHugePage
  | MadvDontDump
  | MadvDoDump
  | MadvWipeOnFork
  | MadvKeepOnFork
#ifdef MADV_COLD
  | MadvCold
#endif
#ifdef MADV_PAGEOUT
  | MadvPageOut
#endif
  deriving (Eq, Ord, Show)

instance CIntRepresentable MemAdvice where
  toCInt (MemAdviceKnown known) =
    case known of
      MadvNormal -> (#const MADV_NORMAL)
      MadvRandom -> (#const MADV_RANDOM)
      MadvSequential -> (#const MADV_SEQUENTIAL)
      MadvWillNeed -> (#const MADV_WILLNEED)
      MadvDontNeed -> (#const MADV_DONTNEED)
      MadvFree -> (#const MADV_FREE)
      MadvRemove -> (#const MADV_REMOVE)
      MadvDontFork -> (#const MADV_DONTFORK)
      MadvDoFork -> (#const MADV_DOFORK)
      MadvHWPoison -> (#const MADV_HWPOISON)
#ifdef MADV_SOFT_OFFLINE
      MadvSoftOffline -> (#const MADV_SOFT_OFFLINE)
#endif
      MadvMergeable -> (#const MADV_MERGEABLE)
      MadvUnmergeable -> (#const MADV_UNMERGEABLE)
      MadvHugePage -> (#const MADV_HUGEPAGE)
      MadvNoHugePage -> (#const MADV_NOHUGEPAGE)
      MadvDontDump -> (#const MADV_DONTDUMP)
      MadvDoDump -> (#const MADV_DODUMP)
      MadvWipeOnFork -> (#const MADV_WIPEONFORK)
      MadvKeepOnFork -> (#const MADV_KEEPONFORK)
#ifdef MADV_COLD
      MadvCold -> (#const MADV_COLD)
#endif
#ifdef MADV_PAGEOUT
      MadvPageOut -> (#const MADV_PAGEOUT)
#endif
  toCInt (MemAdviceUnknown unknown) = unknown
  fromCInt advice = case advice  of
    (#const MADV_NORMAL) -> MemAdviceKnown MadvNormal
    (#const MADV_RANDOM) -> MemAdviceKnown MadvRandom
    (#const MADV_SEQUENTIAL) -> MemAdviceKnown MadvSequential
    (#const MADV_WILLNEED) -> MemAdviceKnown MadvWillNeed
    (#const MADV_DONTNEED) -> MemAdviceKnown MadvDontNeed
    (#const MADV_FREE) -> MemAdviceKnown MadvFree
    (#const MADV_REMOVE) -> MemAdviceKnown MadvRemove
    (#const MADV_DONTFORK) -> MemAdviceKnown MadvDontFork
    (#const MADV_DOFORK) -> MemAdviceKnown MadvDoFork
    (#const MADV_HWPOISON) -> MemAdviceKnown MadvHWPoison
#ifdef MADV_SOFT_OFFLINE
    (#const MADV_SOFT_OFFLINE) -> MemAdviceKnown MadvSoftOffline
#endif
    (#const MADV_MERGEABLE) -> MemAdviceKnown MadvMergeable
    (#const MADV_UNMERGEABLE) -> MemAdviceKnown MadvUnmergeable
    (#const MADV_HUGEPAGE) -> MemAdviceKnown MadvHugePage
    (#const MADV_NOHUGEPAGE) -> MemAdviceKnown MadvNoHugePage
    (#const MADV_DONTDUMP) -> MemAdviceKnown MadvDontDump
    (#const MADV_DODUMP) -> MemAdviceKnown MadvDoDump
    (#const MADV_WIPEONFORK) -> MemAdviceKnown MadvWipeOnFork
    (#const MADV_KEEPONFORK) -> MemAdviceKnown MadvKeepOnFork
#ifdef MADV_COLD
    (#const MADV_COLD) -> MemAdviceKnown MadvCold
#endif
#ifdef MADV_PAGEOUT
    (#const MADV_PAGEOUT) -> MemAdviceKnown MadvPageOut
#endif
    unknown -> MemAdviceUnknown unknown

instance ArgFormatting MemAdvice where
  formatArg (MemAdviceUnknown unknown) = IntegerArg (fromIntegral unknown)
  formatArg (MemAdviceKnown t) = FixedStringArg $ case t of
    MadvNormal -> "MADV_NORMAL"
    MadvRandom -> "MADV_RANDOM"
    MadvSequential -> "MADV_SEQUENTIAL"
    MadvWillNeed -> "MADV_WILLNEED"
    MadvDontNeed -> "MADV_DONTNEED"
    MadvFree -> "MADV_FREE"
    MadvRemove -> "MADV_REMOVE"
    MadvDontFork -> "MADV_DONTFORK"
    MadvDoFork -> "MADV_DOFORK"
    MadvHWPoison -> "MADV_HWPOISON"
#ifdef MADV_SOFT_OFFLINE
    MadvSoftOffline -> "MADV_SOFT_OFFLINE"
#endif
    MadvMergeable -> "MADV_MERGEABLE"
    MadvUnmergeable -> "MADV_UNMERGEABLE"
    MadvHugePage -> "MADV_HUGEPAGE"
    MadvNoHugePage -> "MADV_NOHUGEPAGE"
    MadvDontDump -> "MADV_DONTDUMP"
    MadvDoDump -> "MADV_DODUMP"
    MadvWipeOnFork -> "MADV_WIPEONFORK"
    MadvKeepOnFork -> "MADV_KEEPONFORK"
#ifdef MADV_COLD
    MadvCold -> "MADV_COLD"
#endif
#ifdef MADV_PAGEOUT
    MadvPageOut -> "MADV_PAGEOUT"
#endif

