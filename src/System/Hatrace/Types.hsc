{-# LANGUAGE RecordWildCards #-}
#include <unistd.h>
#include <sys/stat.h>
#include <sys/socket.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , GranularAccessMode(..)
  , fileExistence
  , StatStruct(..)
  , TimespecStruct(..)
  , CIntRepresentable(..)
  , HatraceShow(..)
  , addressFamilyName
  , socketTypeName
  , shutdownTypeName
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

addressFamilyName :: CInt -> String
addressFamilyName af = case af of
  (#const AF_UNSPEC) -> "AF_UNSPEC"
  (#const AF_UNIX) -> "AF_UNIX"
  (#const AF_INET) -> "AF_INET"
  (#const AF_AX25) -> "AF_AX25"
  (#const AF_IPX) -> "AF_IPX"
  (#const AF_APPLETALK) -> "AF_APPLETALK"
  (#const AF_NETROM) -> "AF_NETROM"
  (#const AF_BRIDGE) -> "AF_BRIDGE"
  (#const AF_ATMPVC) -> "AF_ATMPVC"
  (#const AF_X25) -> "AF_X25"
  (#const AF_INET6) -> "AF_INET6"
  (#const AF_ROSE) -> "AF_ROSE"
  (#const AF_DECnet) -> "AF_ROSE"
  (#const AF_NETBEUI) -> "AF_NETBEUI"
  (#const AF_SECURITY) -> "AF_SECURITY"
  (#const AF_KEY) -> "AF_KEY"
  (#const AF_NETLINK) -> "AF_NETLINK"
  (#const AF_PACKET) -> "AF_PACKET"
  (#const AF_ASH) -> "AF_ASH"
  (#const AF_ECONET) -> "AF_ECONET"
  (#const AF_ATMSVC) -> "AF_ATMSVC"
  (#const AF_RDS) -> "AF_RDS"
  (#const AF_SNA) -> "AF_SNA"
  (#const AF_IRDA) -> "AF_IRDA"
  (#const AF_PPPOX) -> "AF_PPPOX"
  (#const AF_WANPIPE) -> "AF_WANPIPE"
  (#const AF_LLC) -> "AF_LLC"
  (#const AF_IB) -> "AF_IB"
  (#const AF_MPLS) -> "AF_MPLS"
  (#const AF_CAN) -> "AF_CAN"
  (#const AF_TIPC) -> "AF_TIPC"
  (#const AF_BLUETOOTH) -> "AF_BLUETOOTH"
  (#const AF_IUCV) -> "AF_IUCV"
  (#const AF_RXRPC) -> "AF_RXRPC"
  (#const AF_ISDN) -> "AF_ISDN"
  (#const AF_PHONET) -> "AF_PHONET"
  (#const AF_IEEE802154) -> "AF_IEEE802154"
  (#const AF_CAIF) -> "AF_CAIF"
  (#const AF_ALG) -> "AF_ALG"
  (#const AF_NFC) -> "AF_NFC"
  (#const AF_VSOCK) -> "AF_VSOCK"
  (#const AF_KCM) -> "AF_KCM"
  (#const AF_QIPCRTR) -> "AF_QIPCRTR"
  (#const AF_SMC) -> "AF_SMC"
  (#const AF_XDP) -> "AF_XDP"
  _ -> "AF_" ++ show af

socketTypeName :: CInt -> String
socketTypeName sock = case sock of
  (#const SOCK_STREAM) -> "SOCK_STREAM"
  (#const SOCK_DGRAM) -> "SOCK_DGRAM"
  (#const SOCK_RAW) -> "SOCK_RAW"
  (#const SOCK_RDM) -> "SOCK_RDM"
  (#const SOCK_SEQPACKET) -> "SOCK_SEQPACKET"
  (#const SOCK_DCCP) -> "SOCK_DCCP"
  (#const SOCK_PACKET) -> "SOCK_PACKET"
  _ -> "SOCK_" ++ show sock

shutdownTypeName :: CInt -> String
shutdownTypeName how = case how of
  (#const SHUT_RD) -> "SHUT_RD"
  (#const SHUT_WR) -> "SHUT_WR"
  (#const SHUT_RDWR) -> "SHUT_RDWR"
  _ -> "SHUT_" ++ show how
