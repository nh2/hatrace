{-# LANGUAGE OverloadedStrings #-}
module System.Hatrace.Format
  ( SyscallEnterFormatting(..)
  , SyscallExitFormatting(..)
  , ArgFormatting(..)
  , FormattedSyscall(..)
  , FormattedArg(..)
  , FormattedReturn(..)
  , StringFormattingOptions(..)
  , defaultStringFormattingOptions
  , syscallToString
  , syscallExitToString
  , argPlaceholder
  , formatReturn
  ) where

import           Data.Aeson
import           Data.ByteString (ByteString)
import           Data.List (intercalate)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Encoding.Error as TE
import           Foreign.C.Types (CInt(..), CUInt(..), CLong(..), CULong(..), CSize(..))
import           System.Posix.Types (CMode(..))

class SyscallEnterFormatting a where
  formatSyscallEnter :: a -> FormattedSyscall

class SyscallExitFormatting a where
  formatSyscallExit :: a -> (FormattedSyscall, FormattedReturn)

data FormattedSyscall =
  FormattedSyscall SyscallName
                   [FormattedArg]
  deriving (Eq, Show)

instance ToJSON FormattedSyscall where
  toJSON (FormattedSyscall syscallName args) =
    object [ "name" .= syscallName
           , "args" .= args
           ]

type SyscallName = String

class ArgFormatting a where
  formatArg :: a -> FormattedArg

instance ArgFormatting ByteString where
  formatArg = VarLengthStringArg . T.unpack . TE.decodeUtf8With TE.lenientDecode

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
  | VarLengthStringArg String
  | ListArg [FormattedArg]
  | StructArg [(StructFieldName, FormattedArg)]
  deriving (Eq, Show)

instance ToJSON FormattedArg where
  toJSON arg = case arg of
    FixedArg s -> toJSON s
    VarLengthStringArg s -> toJSON s
    ListArg xs -> toJSON xs
    StructArg fieldValues ->
      object [ T.pack name .= value | (name, value) <- fieldValues ]

data FormattedReturn
  = NoReturn
  | FormattedReturn FormattedArg
  deriving (Eq, Show)

formatReturn :: ArgFormatting a => a -> FormattedReturn
formatReturn = FormattedReturn . formatArg

type StructFieldName = String

data StringFormattingOptions = StringFormattingOptions
  { sfoStringLengthLimit :: Int
  , sfoListLengthLimit :: Int
  , sfoStructFieldsLimit :: Int
  } deriving (Eq, Show)

defaultStringFormattingOptions :: StringFormattingOptions
defaultStringFormattingOptions = StringFormattingOptions
  { sfoStringLengthLimit = 32
  , sfoListLengthLimit = 5
  , sfoStructFieldsLimit = 3
  }

syscallToString :: StringFormattingOptions -> FormattedSyscall -> String
syscallToString options (FormattedSyscall name args) =
  name  ++ "(" ++ (joinWithCommas $ map (argToString options) args) ++ ")"

argToString :: StringFormattingOptions -> FormattedArg -> String
argToString options arg =
  case arg of
    FixedArg s -> s
    VarLengthStringArg s -> limitedString s
    ListArg elements -> listToString elements
    StructArg fields -> structToString fields
  where
    sizeLimited :: Int -> ([a] -> String) -> String -> [a] -> String
    sizeLimited limit f ellipsis xs = case splitAt limit xs of
      (complete, []) -> f complete
      (cut, _) -> f cut ++ ellipsis
    limitedString = sizeLimited (sfoStringLengthLimit options) show "..."
    listToString xs = "[" ++ (limitedList xs) ++ "]"
    limitedList =
      sizeLimited (sfoListLengthLimit options)
                  (joinWithCommas . map (argToString options))
                  ", ..."
    structToString fields = "{" ++ limitedStruct fields ++ "}"
    limitedStruct =
      sizeLimited (sfoStructFieldsLimit options)
                  (joinWithCommas . map structFieldToString)
                  ", ..."
    structFieldToString (fieldName, v) = fieldName ++ "=" ++ (argToString options) v

syscallExitToString :: StringFormattingOptions -> (FormattedSyscall, FormattedReturn) -> String
syscallExitToString options (formattedSyscall, formattedReturn) =
  syscallToString options formattedSyscall ++ returnToString formattedReturn
  where
    returnToString ret = case ret of
      NoReturn -> ""
      FormattedReturn returnArg -> " = " ++ argToString options returnArg

argPlaceholder :: String -> FormattedArg
argPlaceholder = FixedArg

joinWithCommas :: [String] -> String
joinWithCommas = intercalate ", "
