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
import           Data.Word (Word64)
import           Foreign.C.Types (CInt(..), CUInt(..), CLong(..), CULong(..), CSize(..))
import           System.Posix.Types (CMode(..))

class SyscallEnterFormatting a where
  syscallEnterToFormatted :: a -> FormattedSyscall

class SyscallExitFormatting a where
  syscallExitToFormatted :: a -> (FormattedSyscall, FormattedReturn)

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

instance ArgFormatting Word64 where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting CInt where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting CUInt where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting CLong where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting CULong where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting CSize where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting CMode where
  formatArg = IntegerArg . fromIntegral

instance ArgFormatting a => ArgFormatting [a] where
  formatArg = ListArg . map formatArg

data FormattedArg
  = IntegerArg Integer -- using Integer to accept both Int64 and Word64 at the same time
  | FixedStringArg String
  | VarLengthStringArg String
  | ListArg [FormattedArg]
  | StructArg [(StructFieldName, FormattedArg)]
  deriving (Eq, Show)

instance ToJSON FormattedArg where
  toJSON arg = case arg of
    IntegerArg n -> toJSON n
    FixedStringArg s -> toJSON s
    VarLengthStringArg s -> toJSON s
    ListArg xs -> toJSON xs
    StructArg fieldValues ->
      object [ T.pack name .= value | (name, value) <- fieldValues ]

data FormattedReturn
  = NoReturn
  | FormattedReturn FormattedArg
  deriving (Eq, Show)

instance ToJSON FormattedReturn where
  toJSON NoReturn = "success"
  toJSON (FormattedReturn r) = toJSON r

formatReturn :: ArgFormatting a => a -> FormattedReturn
formatReturn = FormattedReturn . formatArg

type StructFieldName = String

data StringFormattingOptions = StringFormattingOptions
  { sfoStringLengthLimit :: Int
  , sfoListLengthLimit :: Int
  , sfoStructFieldsLimit :: Int
  } deriving (Eq, Ord, Show)

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
    IntegerArg n -> show n
    FixedStringArg s -> s
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
argPlaceholder = FixedStringArg

joinWithCommas :: [String] -> String
joinWithCommas = intercalate ", "
