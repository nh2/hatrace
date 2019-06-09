module System.Hatrace.Format
  ( SyscallEnterFormatting(..)
  , SyscallExitFormatting(..)
  , ArgFormatting(..)
  , FormattedSyscall(..)
  , FormattedArg(..)
  , FormattedReturn(..)
  , syscallToString
  , syscallExitToString
  , argPlaceholder
  , formatReturn
  ) where

import Data.ByteString (ByteString)
import Data.List (intercalate)
import Foreign.C.Types (CInt(..), CUInt(..), CLong(..), CULong(..), CSize(..))
import System.Posix.Types (CMode(..))

class SyscallEnterFormatting a where
  formatSyscallEnter :: a -> FormattedSyscall

class SyscallExitFormatting a where
  formatSyscallExit :: a -> (FormattedSyscall, FormattedReturn)

data FormattedSyscall =
  FormattedSyscall SyscallName
                   [FormattedArg]
  deriving (Eq, Show)

type SyscallName = String

class ArgFormatting a where
  formatArg :: a -> FormattedArg

instance ArgFormatting ByteString where
  formatArg = VarLengthArg . show

instance ArgFormatting CInt where
  formatArg = FixedArg . show

instance ArgFormatting CUInt where
  formatArg = FixedArg . show

instance ArgFormatting CLong where
  formatArg = FixedArg . show

instance ArgFormatting CULong where
  formatArg = FixedArg . show

instance ArgFormatting CSize where
  formatArg = FixedArg . show

instance ArgFormatting CMode where
  formatArg = FixedArg . show

instance ArgFormatting a => ArgFormatting [a] where
  formatArg = ListArg . map formatArg

data FormattedArg = FixedArg String
  | VarLengthArg String
  | ListArg [FormattedArg]
  | StructArg [(StructFieldName, FormattedArg)]
  deriving (Eq, Show)

data FormattedReturn
  = NoReturn
  | FormattedReturn FormattedArg
  deriving (Eq, Show)

formatReturn :: ArgFormatting a => a -> FormattedReturn
formatReturn = FormattedReturn . formatArg

type StructFieldName = String

syscallToString :: FormattedSyscall -> String
syscallToString (FormattedSyscall name args) =
  name  ++ "(" ++ (joinWithCommas $ map argToString args) ++ ")"

argToString :: FormattedArg -> String
argToString arg =
  case arg of
    FixedArg s -> s
    VarLengthArg s -> s
    ListArg elements ->
      "[" ++ (joinWithCommas $ map argToString elements) ++ "]"
    StructArg fields ->
      "{" ++ (joinWithCommas $ map structFieldToString fields) ++ "}"
  where
    structFieldToString (fieldName, v) = fieldName ++ "=" ++ argToString v

syscallExitToString :: (FormattedSyscall, FormattedReturn) -> String
syscallExitToString (formattedSyscall, formattedReturn) =
  syscallToString formattedSyscall ++ returnToString formattedReturn
  where
    returnToString ret = case ret of
      NoReturn -> ""
      FormattedReturn returnArg -> " = " ++ argToString returnArg

argPlaceholder :: String -> FormattedArg
argPlaceholder = FixedArg

joinWithCommas :: [String] -> String
joinWithCommas = intercalate ", "
