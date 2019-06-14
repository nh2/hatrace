{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables #-}

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <netinet/in.h>
#include <linux/netlink.h>
#include <linux/if_packet.h>

module System.Hatrace.Types
  ( FileAccessMode(..)
  , GranularAccessMode(..)
  , fileExistence
  , CIntRepresentable(..)
  , HatraceShow(..)
  , SockAddr(..)
  , wrapPeekVariableLength
  , peekSockAddr
  ) where

import           Data.Bits
import qualified Data.ByteString as BS
import           Data.ByteString.Unsafe (unsafeUseAsCStringLen)
import           Data.List (intercalate)
import           Data.Word (Word32, Word64)
import           Foreign.C.Types (CInt(..), CUShort(..), CUInt(..), CULong(..), CChar, CUChar)
import           Foreign.C.String (peekCString, newCString)
import           Foreign.Storable (Storable(..))
import           Foreign.Ptr
import           System.Linux.Ptrace (TracedProcess(..), peekBytes)
import           Data.WideWord.Word128

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


data Inet6Addr = Inet6Addr { s6_addr :: Word128 } -- IPv6 address (16 bytes)
  deriving (Eq, Ord, Show)

data SockAddr
  = SockAddrUnix UnixSockAddr
  | SockAddrInet InetSockAddr
  | SockAddrInet6 Inet6SockAddr
  | SockAddrNetlink NetlinkSockAddr
  | SockAddrPacket PacketSockAddr
  | SockAddrUnsupportedFamily UnsupportedFamilySockAddr
  deriving (Eq, Ord, Show)

data UnixSockAddr = UnixSockAddr
  { sun_family :: !CUShort -- ^ should be AF_UNIX
  , sun_path :: !BS.ByteString
  }
  deriving (Eq, Ord, Show)

data InetAddr = InetAddr { s_addr :: CUInt }
  deriving (Eq, Ord, Show)

data InetSockAddr = InetSockAddr
  { sin_family :: !CUShort -- ^ should be AF_INET
  , sin_port :: !CUShort
  , sin_addr :: !InetAddr
  }
  deriving (Eq, Ord, Show)

data Inet6SockAddr = Inet6SockAddr
  { sin6_family :: !CUShort -- ^ should be AF_INET6
  , sin6_port :: !CUShort -- ^ port number
  , sin6_flowinfo :: !CULong -- ^ IPv6 flow information
  , sin6_addr :: !Inet6Addr -- ^ IPv6 address
  , sin6_scope_id :: !CUInt -- ^ Scope ID
  }
  deriving (Eq, Ord, Show)

data NetlinkSockAddr = NetlinkSockAddr
  { nl_family :: !CUShort
  , nl_pad :: !CUShort
  , nl_pid :: !CInt
  , nl_groups :: !CUInt
  }
  deriving (Eq, Ord, Show)

data PacketSockAddr = PacketSockAddr
  { sll_family :: !CUShort
  , sll_protocol :: !CUShort
  , sll_ifindex :: !Int
  , sll_hatype :: !CUShort
  , sll_pkttype :: !CUChar
  , sll_halen :: !CUChar
  , sll_addr :: !Word64
  }
  deriving (Eq, Ord, Show)

data UnsupportedFamilySockAddr = UnsupportedFamilySockAddr
  { sa_family :: !CUShort
  }
  deriving (Eq, Ord, Show)


wrapPeekVariableLength :: TracedProcess -> Ptr a -> Word64 -> (Ptr CChar -> Word64 -> IO b) -> IO b
wrapPeekVariableLength process remotePtr numBytes f = do
  bytes <- peekBytes process remotePtr (fromIntegral numBytes)
  unsafeUseAsCStringLen bytes (\(ptr, len) -> f ptr (fromIntegral len))

-- TODO: check types with Template Haskell

peekSockAddr :: Ptr CChar -> Word64 -> IO SockAddr
peekSockAddr ptr addrSize = do
  (f :: CUShort) <- #{peek struct sockaddr, sa_family} ptr
  case f of
    (#const AF_UNIX) -> SockAddrUnix <$> peekUnixSockAddr ptr addrSize
    (#const AF_INET) -> SockAddrInet <$> peekInetSockAddr ptr
    (#const AF_INET6) -> SockAddrInet6 <$> peekInet6SockAddr ptr
    (#const AF_NETLINK) -> SockAddrNetlink <$> peekNetlinkSockAddr ptr
    (#const AF_PACKET) -> SockAddrPacket <$> peekPacketSockAddr ptr
    _ -> SockAddrUnsupportedFamily <$> return UnsupportedFamilySockAddr {sa_family = f}


peekUnixSockAddr :: Ptr CChar -> Word64 -> IO UnixSockAddr
peekUnixSockAddr p addrSize = do
  family <- #{peek struct sockaddr_un, sun_family} p
  case addrSize of
    #{size sa_family_t} -> return UnixSockAddr {
                                          sun_family = family,
                                          sun_path = ""
                                          }

    _ -> do
      let pathPtr = #{ptr struct sockaddr_un, sun_path} p :: Ptr CChar
      let pathSize = addrSize - #{size sa_family_t} :: Word64
      path <- BS.packCStringLen (pathPtr, fromIntegral pathSize)
      return UnixSockAddr {
        sun_family = family,
        sun_path = path
      }


peekInetSockAddr :: Ptr CChar  -> IO InetSockAddr
peekInetSockAddr ptr = do
  family <- #{peek struct sockaddr_in, sin_family} ptr
  port   <- #{peek struct sockaddr_in, sin_port} ptr
  addr   <- #{peek struct sockaddr_in, sin_addr} ptr
  return InetSockAddr {
    sin_family = family,
    sin_port = port,
    sin_addr = addr
  }


peekNetlinkSockAddr :: Ptr CChar -> IO NetlinkSockAddr
peekNetlinkSockAddr ptr = do
  family <- #{peek struct sockaddr_nl, nl_family} ptr
  pad   <- #{peek struct sockaddr_nl, nl_pad} ptr
  pid   <- #{peek struct sockaddr_nl, nl_pid} ptr
  groups   <- #{peek struct sockaddr_nl, nl_groups} ptr
  return NetlinkSockAddr {
    nl_family = family,
    nl_pad = pad,
    nl_pid = pid,
    nl_groups = groups
  }


peekInet6SockAddr :: Ptr CChar -> IO Inet6SockAddr
peekInet6SockAddr ptr = do
  family <- #{peek struct sockaddr_in6, sin6_family} ptr
  port   <- #{peek struct sockaddr_in6, sin6_port} ptr
  flowinfo <- #{peek struct sockaddr_in6, sin6_flowinfo} ptr
  addr <- #{peek struct sockaddr_in6, sin6_addr} ptr
  scopeId <- #{peek struct sockaddr_in6, sin6_scope_id} ptr
  return $ Inet6SockAddr {
    sin6_family = family,
    sin6_port = port,
    sin6_flowinfo = flowinfo,
    sin6_addr = addr,
    sin6_scope_id = scopeId
  }


peekPacketSockAddr :: Ptr CChar -> IO PacketSockAddr
peekPacketSockAddr ptr = do
  family <- #{peek struct sockaddr_ll, sll_family} ptr
  protocol <- #{peek struct sockaddr_ll, sll_protocol} ptr
  ifindex <- #{peek struct sockaddr_ll, sll_ifindex} ptr
  hatype <- #{peek struct sockaddr_ll, sll_hatype} ptr
  pkttype <- #{peek struct sockaddr_ll, sll_pkttype} ptr
  halen <- #{peek struct sockaddr_ll, sll_halen} ptr
  addr <- #{peek struct sockaddr_ll, sll_addr} ptr
  return PacketSockAddr {
    sll_family = family,
    sll_protocol = protocol,
    sll_ifindex = ifindex,
    sll_hatype = hatype,
    sll_pkttype = pkttype,
    sll_halen = halen,
    sll_addr = addr
  }


instance Storable Inet6Addr where
  sizeOf _ = #{size struct in6_addr}
  alignment _ = #{alignment struct in6_addr}
  peek ptr = do
    addr <- #{peek struct in6_addr, s6_addr} ptr
    return $ Inet6Addr { s6_addr = addr }
  poke ptr (Inet6Addr addr) = do
    #{poke struct in6_addr, s6_addr} ptr addr


instance Storable InetAddr where
  sizeOf _ = #{size struct in_addr}
  alignment _ = #{alignment struct in_addr}
  peek ptr = do
    addr <- #{peek struct in_addr, s_addr} ptr
    return $ InetAddr { s_addr = addr}
  poke ptr (InetAddr addr) = do
    #{poke struct in_addr, s_addr} ptr addr
