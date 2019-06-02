{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE ScopedTypeVariables #-}

#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

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
import           Data.Word (Word64)
import           Foreign.C.Types (CInt(..), CUShort(..), CUInt(..), CULong(..), CChar)
import           Foreign.C.String (CString, peekCString, newCString)
import           Foreign.Storable (Storable(..))
import           Foreign.Ptr
import           System.Linux.Ptrace (TracedProcess(..), peekBytes)

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


data Inet6Addr = Inet6Adrr BS.ByteString -- IPv6 address (16 bytes)
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

data InetSockAddr = InetSockAddr
  { sin_family :: !CUShort -- ^ should be AF_INET
  , sin_port :: !CUShort
  , sin_addr :: !CULong
  , sin_zero :: !BS.ByteString
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
  { nl_pad :: !CUShort
  , nl_pid :: !CInt
  , nl_groups :: !CUInt
  }
  deriving (Eq, Ord, Show)

data PacketSockAddr = PacketSockAddr
  { sll_protocol :: !CUShort
  , sll_ifindex :: !Int
  , sll_hatype :: !CUShort
  , sll_pttype :: !Char
  , sll_halen :: !Char
  , sll_len :: !BS.ByteString
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
    (#const AF_INET) -> SockAddrUnix <$> peekUnixSockAddr ptr addrSize
    (#const AF_INET6) -> SockAddrUnsupportedFamily <$> return UnsupportedFamilySockAddr {sa_family = f}
    (#const AF_NETLINK) -> SockAddrUnsupportedFamily <$> return UnsupportedFamilySockAddr {sa_family = f}
    (#const AF_PACKET) -> SockAddrUnsupportedFamily <$> return UnsupportedFamilySockAddr {sa_family = f}
    _ -> SockAddrUnsupportedFamily <$> return UnsupportedFamilySockAddr {sa_family = f}


peekUnixSockAddr :: Ptr CChar -> Word64 -> IO UnixSockAddr
peekUnixSockAddr p addrSize = do
  family <- #{peek struct sockaddr_un, sun_family} p
  print $ "FAMILY: " ++ show family
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


instance Storable SockAddr where
  sizeOf _ = #{size struct sockaddr}
  alignment _ = #{alignment struct sockaddr}
  peek p = do
    f <- #{peek struct sockaddr, sa_family} p
    let d =
          case f of
            (#const AF_UNIX) -> "Unix"
            (#const AF_INET) -> "Inet"
            (#const AF_INET6) -> "Inet6"
            (#const AF_NETLINK) -> "Netlink"
            (#const AF_PACKET) -> "Packet"
            _ -> "Unknown"
    return $ SockAddrUnsupportedFamily UnsupportedFamilySockAddr
        { sa_family = f
        }
  poke p sockAddr = undefined
