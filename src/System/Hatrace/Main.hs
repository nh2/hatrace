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
import           Options.Applicative ( Parser, argument, auto, str, metavar, flag', long, help
                                     , option, value)
import qualified Options.Applicative as Opts
import           System.Exit (exitWith)
import           System.FilePath (splitPath)

import           System.Hatrace
import           System.Hatrace.Format

data Filter
  = FilterAtomicWrites
  | FilterIntheritedFlocks
  deriving (Eq, Ord, Show)

-- | Command line arguments of this program.
data CLIArgs = CLIArgs
  { cliProgram :: FilePath
  , cliArgs :: [String]
  , cliRunMode :: RunMode
  } deriving (Eq, Ord, Show)

data RunMode
  = FilterMode Filter
  | TraceMode OutputOptions
  deriving (Eq, Ord, Show)

data OutputOptions
  = JsonOutput
  | StandardOutput StringFormattingOptions
  deriving (Eq, Ord, Show)

cliArgsParser :: Parser CLIArgs
cliArgsParser = do
  cliRunMode <- modeParser
  cliProgram <- argument str (metavar "PROGRAM")
  cliArgs <- many (argument str (metavar "PROGRAM_ARG"))
  pure $ CLIArgs{ cliProgram, cliArgs, cliRunMode }

modeParser :: Parser RunMode
modeParser =
  filterParser Opts.<|> filterInheritedFlocksParser Opts.<|> traceParser
  where
    filterParser = flag' (FilterMode FilterAtomicWrites)
                   ( long "find-nonatomic-writes"
                   <> help "find file writes without a following rename to a persistent location" )
    filterInheritedFlocksParser =
      flag' (FilterMode FilterIntheritedFlocks)
        ( long "find-inherited-flocks"
        <> help "find flock()s on locks that were inherided forked threads/processes" )
    traceParser = TraceMode <$> (traceJsonParser Opts.<|> traceStdParser)
    traceJsonParser = flag' JsonOutput
                      ( long "json-output"
                      <> help "use JSON for output formatting" )
    traceStdParser = StandardOutput <$> stringOptionsParser

stringOptionsParser :: Parser StringFormattingOptions
stringOptionsParser = do
  sfoStringLengthLimit <- option auto
                          ( long "string-length-limit"
                          <> value (sfoStringLengthLimit defaultStringFormattingOptions)
                          <> help "set upper length limit for strings in output" )
  sfoListLengthLimit <- option auto
                          ( long "list-length-limit"
                          <> value (sfoListLengthLimit defaultStringFormattingOptions)
                          <> help "set upper length limit for number of list elements in output" )
  sfoStructFieldsLimit <- option auto
                          ( long "struct-field-num-limit"
                          <> value (sfoStructFieldsLimit defaultStringFormattingOptions)
                          <> help "set upper length limit for number of struct fields in output" )
  pure $ StringFormattingOptions{ sfoStringLengthLimit
                                , sfoListLengthLimit
                                , sfoStructFieldsLimit }

-- | Parses the command line arguments for this program.
parseArgs :: IO CLIArgs
parseArgs = Opts.execParser $
  Opts.info
    (Opts.helper <*> cliArgsParser)
    (Opts.forwardOptions
     <> Opts.fullDesc
     <> Opts.progDesc "scriptable strace - trace system calls, signals and more")


main :: IO ()
main = do
  CLIArgs
    { cliProgram
    , cliArgs
    , cliRunMode
    } <- parseArgs

  case cliRunMode of
    TraceMode outputFormat -> do
      let printer = case outputFormat of
            JsonOutput -> printHatraceEventJson
            StandardOutput opts -> printHatraceEvent opts
      exitCode <- traceForkProcess cliProgram cliArgs printer
      exitWith exitCode
    FilterMode FilterAtomicWrites -> do
      argv <- procToArgv cliProgram cliArgs
      (exitCode, entries) <- sourceRawTraceForkExecvFullPathWithSink argv atomicWritesSink
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
    FilterMode FilterIntheritedFlocks -> do
      argv <- procToArgv cliProgram cliArgs
      res <- sourceRawTraceForkExecvFullPathWithSink argv inheritedFlocksSink
      print res

maybeNonatomicOrBad :: FilePath -> FileWriteBehavior -> Maybe (Either FilePath (FilePath, String))
maybeNonatomicOrBad _ NoWrites = Nothing
maybeNonatomicOrBad _ (AtomicWrite _) = Nothing
maybeNonatomicOrBad fp NonatomicWrite = Just (Left fp)
maybeNonatomicOrBad fp (Unexpected err) = Just (Right (fp, err))
