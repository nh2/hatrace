{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | @hatrace@ entry point.
module System.Hatrace.Main where

import           Control.Applicative (many)
import           Control.Monad.IO.Class (MonadIO, liftIO)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BS8
import           Data.Conduit
import qualified Data.Conduit.List as CL
import           Data.List (intercalate)
import           Options.Applicative (Parser, argument, str, metavar)
import qualified Options.Applicative as Opts
import           System.Exit (exitWith)

import           System.Hatrace


-- | Command line arguments of this program.
data CLIArgs = CLIArgs
  { cliProgram :: FilePath
  , cliArgs :: [String]
  } deriving (Eq, Ord, Show)


cliArgsParser :: Parser CLIArgs
cliArgsParser = do
  cliProgram <- argument str (metavar "PROGRAM")
  cliArgs <- many (argument str (metavar "PROGRAM_ARG"))
  pure $ CLIArgs{ cliProgram, cliArgs }


-- | Parses the command line arguments for this program.
parseArgs :: IO CLIArgs
parseArgs = Opts.execParser $
  Opts.info
    (Opts.helper <*> cliArgsParser)
    (Opts.fullDesc <> Opts.progDesc "scriptable strace - trace system calls, signals and more")


main :: IO ()
main = do
  CLIArgs
    { cliProgram
    , cliArgs
    } <- parseArgs

  argv <- procToArgv cliProgram cliArgs
  -- (exitCode, ()) <-
  --   sourceTraceForkExecvFullPathWithSink argv (printSyscallOrSignalNameConduit .| CL.sinkNull)
  let printExecvesConduit :: (MonadIO m) => ConduitT (Int, [ByteString]) Void m ()
      printExecvesConduit = CL.mapM_ $ \(depth, execArgv) -> liftIO $ do
        let indent = replicate (2*depth) ' '
        putStrLn $ indent ++ intercalate " " (map BS8.unpack execArgv)
  (exitCode, execvTree) <-
    sourceTraceForkExecvFullPathWithSink argv (( {-printSyscallOrSignalNameConduit .|-} execvTreeConduit) `fuseUpstream` printExecvesConduit)

  -- TODO Format tree nicely
  putStrLn $ "Final tree:"
  putStrLn $ show execvTree

  exitWith exitCode
