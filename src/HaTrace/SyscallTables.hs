module HaTrace.SyscallTables
  ( parseSyscallTable
  , readSyscallTable
  ) where

import qualified Data.ByteString as BS
import           Data.Maybe (listToMaybe)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Data.Word (Word64)
import           Text.Read (readMaybe)


parseSyscallTable :: Text -> [(String, Maybe Word64)]
parseSyscallTable contents = concat $
  [ [ (name, parseNumberOrError <$> listToMaybe rest)
    | name:rest <- [T.unpack <$> T.words (T.strip l)]
    ]
  | l <- T.lines contents
  ]
  where
    parseNumberOrError :: String -> Word64
    parseNumberOrError str = case readMaybe str of
      Just x -> x
      Nothing -> error $ "parseSyscallTable: Not a number: " ++ str


readSyscallTable :: FilePath -> IO [(String, Maybe Word64)]
readSyscallTable path = parseSyscallTable . utf8OrError <$> BS.readFile path
  where
    utf8OrError bs = case T.decodeUtf8' bs of
      Left err -> error $ "readSyscallTable: non-UTF8 in " ++ path ++ ": " ++ show err
      Right text -> text
