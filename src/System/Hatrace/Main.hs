{-# LANGUAGE ApplicativeDo #-}
{-# LANGUAGE LambdaCase #-}
{-# LANGUAGE MultiWayIf #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}

-- | @hatrace@ entry point.
module System.Hatrace.Main where

import           Control.Applicative (many)
import           Control.Monad (forM_, unless)
import           Data.Either (partitionEithers)
import qualified Data.Map as Map
import           Options.Applicative (Parser, argument, str, metavar, flag', long, help, optional, switch)
import qualified Options.Applicative as Opts
import           System.Exit (exitWith)
import           System.FilePath (splitPath)

import           System.Hatrace

data Filter =
  FilterAtomicWrites
  deriving (Eq, Ord, Show)

-- | Command line arguments of this program.
data CLIArgs = CLIArgs
  { cliProgram :: FilePath
  , cliArgs :: [String]
  , cliFilter :: Maybe Filter
  , cliJsonOutput :: Bool
  } deriving (Eq, Ord, Show)


cliArgsParser :: Parser CLIArgs
cliArgsParser = do
  cliProgram <- argument str (metavar "PROGRAM")
  cliArgs <- many (argument str (metavar "PROGRAM_ARG"))
  cliFilter <- optional $ flag' FilterAtomicWrites
              ( long "find-nonatomic-writes"
              <> help "find file writes without a following rename to a persistent location" )
  cliJsonOutput <- switch
                   ( long "json-output"
                   <> help "use JSON for output formatting" )
  pure $ CLIArgs{ cliProgram, cliArgs, cliFilter, cliJsonOutput }


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
    , cliFilter
    , cliJsonOutput
    } <- parseArgs

  case cliFilter of
    Nothing -> do
      let printer = if cliJsonOutput
                    then printHatraceEventJson
                    else printHatraceEvent
      exitCode <- traceForkProcess cliProgram cliArgs printer
      exitWith exitCode
    Just FilterAtomicWrites -> do
      argv <- procToArgv cliProgram cliArgs
      (exitCode, entries) <- sourceTraceForkExecvFullPathWithSink argv atomicWritesSink
      let ignoredPath [] = error "paths are not supposed to be empty"
          ignoredPath ('/':fromRoot) =
            head (splitPath fromRoot) `elem` ["proc/", "dev/", "sys/"]
          ignoredPath _ = True -- pipes and other special paths
          (nonatomic, bad) = partitionEithers . Map.elems $
                             Map.mapMaybeWithKey maybeNonatomicOrBad $
                             Map.filterWithKey (\fp _ -> not $ ignoredPath fp) entries
      unless (null nonatomic) $ do
        putStrLn "The following files were written nonatomically by the program:"
        forM_ nonatomic $ \p -> putStrLn $ " - " ++ show p
      unless (null bad) $ do
        putStrLn "The following files could not be properly analyzed:"
        forM_ bad $ \(p, e) -> do
          putStrLn $ " - " ++ show p ++ ": " ++ e
      exitWith exitCode

maybeNonatomicOrBad :: FilePath -> FileWriteBehavior -> Maybe (Either FilePath (FilePath, String))
maybeNonatomicOrBad _ NoWrites = Nothing
maybeNonatomicOrBad _ (AtomicWrite _) = Nothing
maybeNonatomicOrBad fp NonatomicWrite = Just (Left fp)
maybeNonatomicOrBad fp (Unexpected err) = Just (Right (fp, err))
