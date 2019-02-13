{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | @hatrace@ entry point.
module System.Hatrace.Main where

import           Control.Applicative (many)
import           Options.Applicative (Parser, argument, str, metavar)
import qualified Options.Applicative as Opts
import           System.Exit (exitWith)

import           System.Hatrace (traceForkProcess)


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

  exitCode <- traceForkProcess cliProgram cliArgs
  exitWith exitCode
