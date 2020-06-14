{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}
{-# LANGUAGE CPP #-}
{-# LANGUAGE LambdaCase #-}

module HatraceSpec where

import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.IO.Unlift (MonadUnliftIO)
import           Data.ByteString (ByteString)
import qualified Data.ByteString as BS
import           Data.Conduit
import qualified Data.Conduit.Combinators as CC
import qualified Data.Conduit.List as CL
import qualified Data.List as List
import qualified Data.Map as Map
import           Data.Maybe (fromMaybe)
import           Data.Set (Set)
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Foreign.C.Error (Errno(..), eBADF, eCONNRESET)
import           Foreign.Marshal.Alloc (alloca)
import           Foreign.Ptr (nullPtr, plusPtr)
import           Foreign.Storable (sizeOf, peek, poke)
import           System.FilePath (takeFileName, takeDirectory)
import           System.Directory (doesFileExist, removeFile)
import           System.Exit
import           System.IO.Temp (withSystemTempDirectory, emptySystemTempFile)
import           System.Posix.Files (getFileStatus, fileSize, readSymbolicLink)
import           System.Posix.Resource (Resource(..), ResourceLimit(..), ResourceLimits(..), getResourceLimit, setResourceLimit)
import           System.Posix.Signals (sigCHLD, sigTERM, sigUSR1, sigINT, sigSYS, sigQUIT, sigKILL)
import           System.Posix.User (getRealUserID, getRealGroupID, getEffectiveUserID, getEffectiveGroupID)
import           System.Process (callProcess, readProcess)
import           Test.Hspec
import           Test.Hspec.QuickCheck
import           Text.Read (readMaybe)
import           UnliftIO.Exception (bracket)

import System.Hatrace
import System.Hatrace.Format
import System.Hatrace.Types


-- | Assertion we run before each test to ensure no leftover child processes
-- that could affect subsequent tests.
--
-- This is obviously not effective if tests were to run in parallel.
assertNoChildren :: IO ()
assertNoChildren = do
  hasChildren <- doesProcessHaveChildren
  when hasChildren $ do
    error "You have children you don't know of, probably from a previous test"


withCoredumpsDisabled :: (MonadUnliftIO m) => m a -> m a
withCoredumpsDisabled f = do
  bracket
    (liftIO $ getResourceLimit ResourceCoreFileSize)
    (\coreLimit -> liftIO $ setResourceLimit ResourceCoreFileSize coreLimit)
    $ \coreLimit -> do
      liftIO $ setResourceLimit ResourceCoreFileSize coreLimit{ softLimit = ResourceLimit 0 }
      f

makeAtomicWriteExample :: IO ()
makeAtomicWriteExample =
  callProcess "make" ["--quiet", "example-programs-build/atomic-write"]

spec :: Spec
spec = before_ assertNoChildren $ do
  -- Note we use `before_` instead of `after_` above because apparently,
  -- hspec swallows test failure messages if after the test faulure the
  -- `after_` action fails as well, showing only the latter's message.

  let muted _ = return ()

  describe "traceCreateProcess" $ do

    it "does not crash for this echo process" $ do
      traceForkProcess "echo" ["hello"] muted  `shouldReturn` ExitSuccess

    -- TODO Instead of compiling things here with `make`, do it as a Cabal hook.

    it "does not crash for hello.asm with 32-bit API" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-i386-elf64"]
      traceForkProcess "example-programs-build/hello-linux-i386-elf64" [] muted `shouldReturn` ExitSuccess

    it "does not crash for hello.asm real 32-bit" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-i386"]
      traceForkProcess "example-programs-build/hello-linux-i386" [] muted `shouldReturn` ExitSuccess

    it "does not crash for hello.asm with 64-bit API" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
      traceForkProcess "example-programs-build/hello-linux-x86_64" [] muted `shouldReturn` ExitSuccess

    it "does not hang when the traced program segfaults" $ do
      callProcess "make" ["--quiet", "example-programs-build/segfault"]
      -- Disable core dumps for the test to not litter in the working tree.
      withCoredumpsDisabled $ do
        -- Note: Despite disabling core dump files by setting RLIMIT_CORE to 0,
        -- on some systems, the core dump flag (128) will still be set after a
        -- crash.
        --
        -- This happens when /proc/sys/kernel/core_pattern is set to a value
        -- that starts with a pipe, triggering the execution of a handling
        -- program, no matter what value RLIMIT_CORE is set to. We unfortunately
        -- can change this setting neither only for our processes nor without
        -- root privileges. We therefore simply ignore the core dump flag if
        -- present.
        --
        -- See also: core(5) - accessible by running `man 5 core`.
        exitCode <- traceForkProcess "example-programs-build/segfault" [] muted
        exitCode `shouldSatisfy` \x ->
          x `elem` [ExitFailure 11, ExitFailure (128+11)]

  describe "sourceRawTraceForkExecvFullPathWithSink" $ do

    it "lets the process finish if the sink exits early" $ do
      argv <- procToArgv "echo" ["hello"]
      (exitCode, ()) <- sourceRawTraceForkExecvFullPathWithSink argv (return ())
      exitCode `shouldBe` ExitSuccess

    it "allows obtaining all syscalls as a list for hello.asm" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
      argv <- procToArgv "example-programs-build/hello-linux-x86_64" []
      (exitCode, events) <- sourceRawTraceForkExecvFullPathWithSink argv CL.consume

      let syscalls = [ syscall | (_pid, SyscallStop SyscallEnter (syscall, _args)) <- events ]
      exitCode `shouldBe` ExitSuccess
      syscalls `shouldBe`
        [ KnownSyscall Syscall_execve
        , KnownSyscall Syscall_write
        , KnownSyscall Syscall_exit
        ]

    it "shows return code and errno of a failing write() syscall" $ do
      callProcess "make" ["--quiet", "example-programs-build/write-EBADF"]
      argv <- procToArgv "example-programs-build/write-EBADF" []
      (exitCode, events) <-
        sourceRawTraceForkExecvFullPathWithSink argv $
          syscallRawExitDetailsOnlyConduit .| CL.consume
      let writeErrnos =
            -- We filter for writes, as the test program is written in C and
            -- may make some syscalls that set errno, e.g.
            --     access("/etc/ld.so.nohwcap", F_OK) = -1 ENOENT
            -- on the Ubuntu 16.04 this was written on.
            [ errno | (_pid, Left (KnownSyscall Syscall_write, errno)) <- events ]
      exitCode `shouldBe` ExitFailure 1
      writeErrnos `shouldBe`
        [ foreignErrnoToERRNO eBADF
        ]

    describe "subprocess tracing" $ do

      it "can trace 'bash -c ./hello'" $ do
        callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
        -- We must run *something* (e.g. `&& true`) after the program,
        -- otherwise bash will just execve() and not fork() at all, in which case
        -- this test wouldn't actually test tracing into subprocesses.
        argv <- procToArgv "bash" ["-c", "example-programs-build/hello-linux-x86_64 && true"]
        (exitCode, events) <- sourceRawTraceForkExecvFullPathWithSink argv CL.consume
        let cloneWriteSyscalls =
              [ syscall
              | (_pid, SyscallStop SyscallEnter (KnownSyscall syscall, _args)) <- events
              , syscall `elem` [Syscall_clone, Syscall_write]
              ]
        exitCode `shouldBe` ExitSuccess
        cloneWriteSyscalls `shouldBe` [Syscall_clone, Syscall_write]

      it "can handle the situation that the child doesn't wait for its children" $ do
        pendingWith "implement test with simple C program that doens't wait for a child"

      it "can handle the situation that a child's child double-forks" $ do
        pendingWith "implement test with simple C program that has a child double-fork"

      it "can handle Group-stop in multithreaded programs" $ do
        pendingWith "implement test with simple C program that uses multiple threads"

  describe "program inspection" $ do

    it "can point out that the difference in syscalls between atomic and non-atomic write is a rename" $ do

      makeAtomicWriteExample
      let getSyscallsSetFor :: [String] -> IO (Set Syscall)
          getSyscallsSetFor args = do
            argv <- procToArgv "example-programs-build/atomic-write" args
            (exitCode, events) <- sourceRawTraceForkExecvFullPathWithSink argv CL.consume
            let syscalls = [ syscall | (_pid, SyscallStop SyscallEnter (syscall, _args)) <- events ]
            exitCode `shouldBe` ExitSuccess
            return (Set.fromList syscalls)

      -- Don't pick this it too large, because `atomic-write` writes only
      -- 1 character per syscall, and ptrace() makes syscalls slow.
      let numBytes = 100 :: Int
      syscallsAtomic <- getSyscallsSetFor ["atomic", show numBytes, "example-programs-build/testfile"]
      syscallsNonAtomic <- getSyscallsSetFor ["non-atomic", show numBytes, "example-programs-build/testfile"]

      let differenceInSyscalls = syscallsAtomic `Set.difference` syscallsNonAtomic

      differenceInSyscalls `shouldBe` Set.fromList [KnownSyscall Syscall_rename]

  describe "program misbehaviour detection" $ do

    it "can show that SIGTERM at the right time results in cut-off files for non-atomically writing programs" $ do

      let targetFile = "example-programs-build/testfile-for-sigterm"

      let killAfter3Writes :: String -> IO ()
          killAfter3Writes atomicityFlag = do
            callProcess "make" ["--quiet", "example-programs-build/atomic-write"]
            let numBytes = 100 :: Int
            argv <- procToArgv "example-programs-build/atomic-write" [atomicityFlag, show numBytes, targetFile]

            let isWrite (_pid, SyscallStop SyscallEnter (KnownSyscall Syscall_write, _args)) = True
                isWrite _ = False

            -- We have to use SIGTERM and cannot use SIGKILL as of writing,
            -- because Hatrace cannot yet handle the case where the tracee
            -- instantly goes away: we get in that case:
            --     ptrace: does not exist (No such process)
            -- For showing the below, SIGTERM is good enough for now.
            let killConduit =
                  awaitForever $ \(pid, _) -> liftIO $ sendSignal pid sigTERM

                -- Filters away everything that's not a write syscall,
                -- and at the onset of the 4th write, SIGTERMs the process.
                killAt4thWriteConduit =
                  CC.filter isWrite .| (CC.drop 3 >> killConduit)

            _ <- sourceRawTraceForkExecvFullPathWithSink argv killAt4thWriteConduit

            return ()

      -- Writing the file non-atomically should result in truncated contents.
      -- There should be 3 'a's in the file, as we killed after 3 writes.
      killAfter3Writes "non-atomic"
      fileContents <- BS.readFile targetFile
      -- Because we send a TERM at the onset of the 4th write, we don't know
      -- which will happen first, so the 4th write may succeed or not.
      -- TODO: This *might* still be racy, because signal delivery can be
      --       arbitrarily delayed.
      fileContents `shouldSatisfy` (`elem` ["aaa", "aaaa"])

      removeFile targetFile

      -- Writing the file atomically should result in it not existing at all.
      killAfter3Writes "atomic"
      targetExists <- doesFileExist targetFile
      targetExists `shouldBe` False

    it "can be used to check whether GHC writes truncated object files or executables" $ do

      let targetFile = "example-programs-build/haskell-hello"
      -- Note that which GHC is used depends on PATH.
      -- When the test is executed via stack, cabal, nix etc, the GHC is fixed
      -- though, so this note is only relevant if you run the test executable
      -- directly from the terminal, or want to give your own GHC (see below).
      let program = "env"
      let ghc = "ghc"
      -- For my fixed GHC
      -- let ghc = "/raid/src/ghc/ghc-atomic-writes/_build/stage1/bin/ghc"
      -- So that a custom path can be given conveniently when testing a patch.
      -- You probably want to set GHC_PACKAGE_PATH below when doing that so that
      -- your custom GHC works even under `stack test`.
      let isPatchedGhc = ghc /= "ghc"
      let args =
            [ ghc
            -- For my fixed GHC
            -- Note it's very important that GHC_PACKAGE_PATH does not end with a '/',
            -- see https://gitlab.haskell.org/ghc/ghc/issues/16360
            -- [ "GHC_PACKAGE_PATH=/raid/src/ghc/ghc-atomic-writes/_build/stage1/lib/package.conf.d", ghc
            , "--make"
            , "-outputdir", "example-programs-build/"
            , "example-programs/Hello.hs"
            , "-o", targetFile
            ]

      ghcVersionOuput <- readProcess ghc ["--numeric-version"] ""
      -- The bug was fixed in GHC 8.8
      -- TODO Link to commit that fixes it;
      --      the GHC `master` commit is https://gitlab.haskell.org/ghc/ghc/merge_requests/391
      --      but it isn't picked on top of the 8.8 release branch yet
      let isBuggedGhc
            | isPatchedGhc = False
            | otherwise =
                case T.splitOn "." $ T.strip $ T.pack ghcVersionOuput of
                  majorText:minorText:_
                    | Just (major :: Int) <- readMaybe (T.unpack majorText)
                    , Just (minor :: Int) <- readMaybe (T.unpack minorText)
                      -> (major, minor) <= (8,8)
                  _ -> error $ "Could not parse ghc version: " ++ ghcVersionOuput


      let runGhcMakeFullBuildWithKill :: IO ()
          runGhcMakeFullBuildWithKill = do
            argv <- procToArgv program (args ++ ["-fforce-recomp"])

            -- Note: Newer GHCs link with GNU gold by default,
            -- which does not issue write() syscalls to write the final
            -- executable, but uses fallocate()+mmap() instead.
            -- We may still be able to kill gold at the right time to end up
            -- with a half-written executable, but we cannot time it via
            -- observing syscalls.
            -- So we focus on GHC's `.o` files here instead of the linker's
            -- executable outputs.

            -- We have to use SIGTERM and cannot use SIGKILL as of writing,
            -- because Hatrace cannot yet handle the case where the tracee
            -- instantly goes away: we get in that case:
            --     ptrace: does not exist (No such process)
            -- For showing the below, SIGTERM is good enough for now.
            let objectFileWriteFilterConduit =
                  awaitForever $ \(pid, exitOrErrno) -> do
                    case exitOrErrno of
                      Left{} -> return () -- ignore erroneous syscalls
                      Right exit -> case exit of
                        DetailedSyscallExit_write
                          SyscallExitDetails_write
                            { enterDetail = SyscallEnterDetails_write{ fd, count } } -> do
                          let procFdPath = "/proc/" ++ show pid ++ "/fd/" ++ show fd
                          fullPath <- liftIO $ readSymbolicLink procFdPath
                          let isRelevantFile =
                                -- Any file in the `-outputdir` that has `Main.o` in the path
                                takeFileName (takeDirectory fullPath) == "example-programs-build"
                                && T.isInfixOf "Main.o" (T.pack fullPath)
                          when isRelevantFile $ do
                            liftIO $ putStrLn $ "Observing write to relevant file: " ++ fullPath ++ "; bytes: " ++ show count
                            yield (pid, fullPath, count)
                        _ -> return ()

            let killConduit =
                  awaitForever $ \(pid, _path, _count) -> liftIO $ do
                    sendSignal pid sigTERM

            (exitCode, ()) <-
              sourceTraceForkExecvFullPathWithSink argv $
                   syscallExitDetailsOnlyConduit
                .| objectFileWriteFilterConduit
                .| (CL.take 3 >> killConduit)
            exitCode `shouldNotBe` ExitSuccess

      -- Delete potentially leftover files from previous build
      callProcess "rm" ["-f", targetFile, "example-programs-build/Main.hi", "example-programs-build/Main.o"]

      -- Build normally, record output file size
      callProcess program args
      expectedSize <- fileSize <$> getFileStatus targetFile

      -- Build build from scratch, with kill
      putStrLn "\nRunning and then killing GHC; expect error messages below.\n"
      runGhcMakeFullBuildWithKill
      putStrLn "\nEnd of where error messages are expected.\n"

      -- Build normally (incrementally), check if results are normal.
      -- A bugged GHC will typically have a linker error due to truncated .o files,
      -- a fixed GHC will run to completion.
      if isBuggedGhc
        then do
          callProcess program args `shouldThrow` anyIOException
        else do
          callProcess program args
          rebuildSize <- fileSize <$> getFileStatus targetFile
          rebuildSize `shouldBe` expectedSize

    it "can be used to check whether programs handle EINTR correctly" $ do
      pendingWith "implement test that uses PTRACE_INTERRUPT in every syscall"

    it "observes atomic write in a program" $ do
        makeAtomicWriteExample
        tmpFile <- emptySystemTempFile "test-output"
        argv <- procToArgv "example-programs-build/atomic-write" ["atomic", "10", tmpFile]
        (exitCode, writes) <-
          sourceRawTraceForkExecvFullPathWithSink argv atomicWritesSink
        exitCode `shouldBe` ExitSuccess
        case Map.lookup tmpFile writes of
          Just (AtomicWrite _) -> return ()
          other -> error $ "atomic write for " ++ show tmpFile ++
                           " was expected but found " ++ show other

    it "catches non-atomic write in a program" $ do
        makeAtomicWriteExample
        tmpFile <- emptySystemTempFile "test-output"
        argv <- procToArgv "example-programs-build/atomic-write" ["non-atomic", "10", tmpFile]
        (exitCode, writes) <-
          sourceRawTraceForkExecvFullPathWithSink argv atomicWritesSink
        exitCode `shouldBe` ExitSuccess
        Map.lookup tmpFile writes `shouldBe` Just NonatomicWrite

  describe "modifying syscalls" $ do

    let changeWriteSyscallResult errorOrRetValue =
          awaitForever $ \(pid, exitOrErrno) -> do
            case exitOrErrno of
              Left _ -> pure ()
              Right syscallExit -> case syscallExit of
                DetailedSyscallExit_write SyscallExitDetails_write{} -> do
                  liftIO $ setExitedSyscallResult pid errorOrRetValue
                _ -> pure ()

    it "can change syscall result to any error" $ do
        let writeCall = "example-programs-build/change-write-result"
        callProcess "make" ["--quiet", writeCall]
        argv <- procToArgv writeCall []
        let injectedErrno@(Errno expectedReturn) =
              eCONNRESET
        -- we don't check events, as we're interested in the actual result of
        -- the syscall, which should be changed and this change needs to be
        -- visible in the traced program
        (exitCode, _) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .|
            changeWriteSyscallResult (Left $ foreignErrnoToERRNO injectedErrno) .|
            CL.consume
        exitCode `shouldBe` (ExitFailure $ fromIntegral expectedReturn)

    it "can change syscall result to any return value" $ do
        let writeCall = "example-programs-build/change-write-result"
        callProcess "make" ["--quiet", writeCall]
        argv <- procToArgv writeCall []
        -- this value below should fit into 8 bits, as exit() does not return
        -- more bits to the parent
        let newRetValue = 67
        -- we don't check events, as we're interested in the actual result of
        -- the syscall, which should be changed and this change needs to be
        -- visible in the traced program
        (exitCode, _) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .|
            changeWriteSyscallResult (Right $ fromIntegral newRetValue) .|
            CL.consume
        exitCode `shouldBe` (ExitFailure newRetValue)

  describe "storable instances" $ do

    it "can correctly poke and peek SigSet" $ do
      let origSigset = List.sort [sigTERM, sigUSR1, sigINT, sigSYS, sigQUIT, sigKILL]
      (SigSet pokedSigset) <- alloca $ \ptr -> do { poke ptr (SigSet origSigset); peek ptr }
      pokedSigset `shouldContain` origSigset

  describe "deriveCIntRepresentable" $ do

    prop "derived toCInt . fromCInt == id for FileAccessMode" $
      \x -> toCInt (fromCInt x :: FileAccessMode) == x

    prop "derived fromCInt . toCInt == id for FileAccessKnown" $
      \(r, w, e) ->
        let access = FileAccessKnown (GranularAccessMode r w e)
        in fromCInt (toCInt access) == access

  describe "per-syscall tests" $ do

    describe "read" $ do

      it "has the right output for 'echo hello | cat'" $ do
        argv <- procToArgv "bash" ["-c", "echo hello | cat > /dev/null"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        let stdinReads =
              [ bufContents
              | (_pid
                , Right (
                    DetailedSyscallExit_read
                      SyscallExitDetails_read
                        { enterDetail = SyscallEnterDetails_read{ fd = 0 }
                        , bufContents
                        }
                  )
                ) <- events
              ]
        exitCode `shouldBe` ExitSuccess
        -- Concatenate because there may be short reads and retries.
        BS.concat stdinReads `shouldBe` "hello\n"

    describe "exit_group" $ do

       it "Syscall_exit_group is identified" $ do
         argv <- procToArgv "true" []
         (exitCode, events) <- sourceRawTraceForkExecvFullPathWithSink argv CL.consume

         let syscalls = [ syscall | (_pid, SyscallStop SyscallEnter (syscall, _args)) <- events ]
         exitCode `shouldBe` ExitSuccess
         syscalls `shouldSatisfy` (\xs -> KnownSyscall Syscall_exit_group `elem` xs)

    describe "lseek" $ do

       it "Syscall_lseek is identified" $ do
         argv <- procToArgv "tail" ["/proc/cpuinfo"]
         (exitCode, events) <- sourceRawTraceForkExecvFullPathWithSink argv CL.consume

         let syscalls = [ syscall | (_pid, SyscallStop SyscallEnter (syscall, _args)) <- events ]
         exitCode `shouldBe` ExitSuccess
         syscalls `shouldSatisfy` (\xs -> KnownSyscall Syscall_lseek `elem` xs)

    describe "execve" $ do

      let runExecveProgram :: FilePath -> FilePath -> IO (ExitCode, [(ByteString, Int)])
          runExecveProgram execveProgram programToExecve = do
            innerArgv <- procToArgv programToExecve []
            argv <- procToArgv execveProgram innerArgv
            (exitCode, events) <-
              sourceTraceForkExecvFullPathWithSink argv $
                syscallExitDetailsOnlyConduit .| CL.consume
            let execveDetails =
                  [ (filenameBS, fromIntegral execveResult)
                  | ( _pid
                    , Right (DetailedSyscallExit_execve
                             SyscallExitDetails_execve
                               { optionalEnterDetail = Just SyscallEnterDetails_execve
                                   { filenameBS }
                               , execveResult})
                    ) <- events
                  ]
            return (exitCode, execveDetails)

      it "shows the right execve results for './execve hello-linux-x86_64'" $ do

        let program1 = "example-programs-build/execve"
            program2 = "example-programs-build/hello-linux-x86_64"
        callProcess "make" ["--quiet", program1, program2]
        (exitCode, execveDetails) <- runExecveProgram program1 program2
        exitCode `shouldBe` ExitSuccess
        -- There should be one execve() for our C program being started by the
        -- test process, and one by the program that it execve()s.
        execveDetails `shouldBe`
          [ (T.encodeUtf8 $ T.pack program1, 0)
          , (T.encodeUtf8 $ T.pack program2, 0)
          ]

      it "shows the right execve results for the special case './execve-linux-null-envp hello-linux-x86_64'" $ do

        let program1 = "example-programs-build/execve-linux-null-envp"
            program2 = "example-programs-build/hello-linux-x86_64"
        callProcess "make" ["--quiet", program1, program2]
        (exitCode, execveDetails) <- runExecveProgram program1 program2
        exitCode `shouldBe` ExitSuccess
        -- There should be one execve() for our C program being started by the
        -- test process, and one by the program that it execve()s.
        execveDetails `shouldBe`
          [ (T.encodeUtf8 $ T.pack program1, 0)
          , (T.encodeUtf8 $ T.pack program2, 0)
          ]


    describe "close" $ do
      it "seen at least for 1 file for 'cat /dev/null'" $ do
        argv <- procToArgv "cat" ["/dev/null"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let closeEvents =
              [ detail
              | (_pid
                , Right (DetailedSyscallExit_close detail)
                ) <- events
              ]
        closeEvents `shouldSatisfy` (not . null)

    describe "openat" $ do
      it "seen for a file we open for writing" $ do
        makeAtomicWriteExample
        tmpFile <- emptySystemTempFile "test-output"
        argv <- procToArgv "example-programs-build/atomic-write" ["non-atomic", "10", tmpFile]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        -- Some libcs use `open()`, some `openat()`.
        let tmpFileOpenEvents =
              [ pathnameBS
              | (_pid
                , Right (DetailedSyscallExit_open
                         SyscallExitDetails_open
                         { enterDetail = SyscallEnterDetails_open{ pathnameBS }})
                ) <- events
                , pathnameBS == T.encodeUtf8 (T.pack tmpFile)
              ]
        let tmpFileOpenatEvents =
              [ pathnameBS
              | (_pid
                , Right (DetailedSyscallExit_openat
                         SyscallExitDetails_openat
                         { enterDetail = SyscallEnterDetails_openat{ pathnameBS }})
                ) <- events
                , pathnameBS == T.encodeUtf8 (T.pack tmpFile)
              ]
        let allTmpFileOpenEvents = tmpFileOpenEvents ++ tmpFileOpenatEvents
        allTmpFileOpenEvents `shouldSatisfy` (not . null)

    describe "rename" $ do
      it "seen for a file we do an atomic write to" $ do
        makeAtomicWriteExample
        tmpFile <- emptySystemTempFile "test-output"
        argv <- procToArgv "example-programs-build/atomic-write" ["atomic", "10", tmpFile]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let renameToTmpFileEvents =
              [ newpathBS
              | (_pid
                , Right (DetailedSyscallExit_rename
                         SyscallExitDetails_rename
                         { enterDetail = SyscallEnterDetails_rename{ newpathBS }})
                ) <- events
                , newpathBS == T.encodeUtf8 (T.pack tmpFile)
              ]
        renameToTmpFileEvents `shouldSatisfy` (not . null)

    describe "unlink" $ do
      it "occurs when we delete a file" $ do
        fileToUnlink <- emptySystemTempFile "unlink-test"
        let testProgram = "example-programs-build/unlink"
        callProcess "make" ["--quiet", testProgram]
        argv <- procToArgv testProgram [fileToUnlink]
        (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv $
          syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let unlinkedFiles =
              [ fileToUnlink
              | (_pid
                , Right (DetailedSyscallExit_unlink
                          SyscallExitDetails_unlink
                          { enterDetail = SyscallEnterDetails_unlink { pathnameBS }
                          })
                ) <- events
              , pathnameBS == T.encodeUtf8 (T.pack fileToUnlink)
              ]
        unlinkedFiles `shouldBe` [fileToUnlink]

    describe "pipe" $ do
      it "seen when piping output in bash" $ do
        argv <- procToArgv "bash" ["-c", "echo 'foo' | cat"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let pipeEvents =
              [ (readfd, writefd)
              | (_pid
                , Right (DetailedSyscallExit_pipe
                         SyscallExitDetails_pipe
                         { enterDetail = SyscallEnterDetails_pipe{}, readfd, writefd })
                ) <- events
              ]
        pipeEvents `shouldSatisfy` (not . null)

    describe "dup" $ do
       it "Syscall_dup2 is identified" $ do
         argv <- procToArgv "sh" ["-c", "echo 'foo' | cat"]
         (exitCode, events) <- sourceRawTraceForkExecvFullPathWithSink argv CL.consume

         let syscalls = [ syscall | (_pid, SyscallStop SyscallEnter (syscall, _args)) <- events ]
         exitCode `shouldBe` ExitSuccess
         syscalls `shouldSatisfy` (\xs -> KnownSyscall Syscall_dup2 `elem` xs)

    describe "access" $ do
      it "seen when invoked in a program" $ do
        let accessItself = "example-programs-build/access-itself"
        callProcess "make" ["--quiet", accessItself]
        argv <- procToArgv accessItself []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let accessModesRequested =
              [ mode
              | (_pid
                , Right (DetailedSyscallExit_access
                         SyscallExitDetails_access
                         { enterDetail = SyscallEnterDetails_access{ mode } })
                ) <- events
              ]
            x_OK = 1
        accessModesRequested `shouldBe` [x_OK]

    describe "sockets" $ do
      it "seen when opening sockets" $ do
        let sockets = "example-programs-build/sockets"
        callProcess "make" ["--quiet", sockets]
        argv <- procToArgv sockets ["socket"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let args =
              [ (domain, type_)
              | (_pid
                , Right (DetailedSyscallExit_socket
                         SyscallExitDetails_socket
                         { enterDetail = SyscallEnterDetails_socket{ domain, type_ } })
                ) <- events
              ]
            (af_UNIX, af_INET, af_INET6) = (1, 2, 10)
            (sock_STREAM, sock_DGRAM) = (1, 2)
        (take 6 args) `shouldBe` [(af_INET, sock_STREAM), (af_INET6, sock_STREAM), (af_INET, sock_DGRAM), (af_INET6, sock_DGRAM), (af_UNIX, sock_STREAM), (af_UNIX, sock_DGRAM)]
      it "seen when opening a socketpair" $ do
        let sockets = "example-programs-build/sockets"
        callProcess "make" ["--quiet", sockets]
        argv <- procToArgv sockets ["socketpair"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let args =
              [ (domain, type_)
              | (_pid
                , Right (DetailedSyscallExit_socketpair
                         SyscallExitDetails_socketpair
                         { enterDetail = SyscallEnterDetails_socketpair{ domain, type_ } })
                ) <- events
              ]
            (af_UNIX, sock_STREAM) = (1, 1)
        args `shouldBe` [(af_UNIX, sock_STREAM)]
      it "seen when using sendto/recvfrom on a socketpair" $ do
        let sockets = "example-programs-build/sockets"
        callProcess "make" ["--quiet", sockets]
        argv <- procToArgv sockets ["sendrecv"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let recv =
              [ bufContents
              | (_pid
                , Right (DetailedSyscallExit_recvfrom
                         SyscallExitDetails_recvfrom
                         { bufContents })
                ) <- events
              ]
        let send =
              [ bufContents
              | (_pid
                , Right (DetailedSyscallExit_sendto
                         SyscallExitDetails_sendto
                         { enterDetail = SyscallEnterDetails_sendto{ bufContents } })
                ) <- events
              ]
        recv `shouldBe` send

    describe "lstat" $ do
      it "seen called by stat executable" $ do
        argv <- procToArgv "stat" ["/dev/null"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let pathsLstatRequested =
              [ pathnameBS
              | (_pid
                , Right (DetailedSyscallExit_lstat
                         SyscallExitDetails_lstat
                         { enterDetail = SyscallEnterDetails_lstat{ pathnameBS } })
                ) <- events
              ]
        pathsLstatRequested `shouldSatisfy` ("/dev/null" `elem`)

    describe "mmap" $ do
      it "sees the correct arguments" $ do
        let mmapSyscall = "example-programs-build/mmap-syscall"
        callProcess "make" ["--quiet", mmapSyscall]
        argv <- procToArgv mmapSyscall []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let mmapArguments =
              [ enterDetail (exitDetails :: SyscallExitDetails_mmap)
              | (_pid
                , Right (DetailedSyscallExit_mmap
                         exitDetails)
                ) <- events
              ]
        let SyscallEnterDetails_mmap
              {addr, len, prot, flags, offset} = last mmapArguments
        addr `shouldBe` nullPtr
        len `shouldBe` fromIntegral (100 :: Int)
        formatArg prot `shouldBe` FixedStringArg "PROT_READ"
        formatArg flags `shouldBe` FixedStringArg "MAP_SHARED"
        offset `shouldBe` fromIntegral (0 :: Int)

    describe "munmap" $ do
      it "sees called by mmap-syscall executable" $ do
        let mmapSyscall = "example-programs-build/mmap-syscall"
        callProcess "make" ["--quiet", mmapSyscall]
        argv <- procToArgv mmapSyscall []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let munmapArguments =
              [ enterDetail (exitDetails :: SyscallExitDetails_munmap)
              | (_pid
                , Right (DetailedSyscallExit_munmap
                         exitDetails)
                ) <- events
              ]
        let SyscallEnterDetails_munmap{addr, len} = last munmapArguments
        addr `shouldNotBe` nullPtr
        len `shouldBe` fromIntegral (100 :: Int)

    describe "time" $ do
      it "seen called by trigger-time executable" $ do
        callProcess "make" ["--quiet", "example-programs-build/trigger-time"]
        argv <- procToArgv "example-programs-build/trigger-time" ["--quiet"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let timeDetails =
              [ (timeResult > 0)
              | (_pid
                , Right (DetailedSyscallExit_time
                         SyscallExitDetails_time
                         { timeResult })
                ) <- events
              ]
        timeDetails `shouldBe` [True, True]

    describe "brk" $ do
      it "has correct output after changing program break" $ do
        let brkCall = "example-programs-build/brk-syscall"
        callProcess "make" ["--quiet", brkCall]
        argv <- procToArgv brkCall []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let brkCallAddresses =
              [ (addr, brkResult)
              | (_pid
                , Right (DetailedSyscallExit_brk
                         SyscallExitDetails_brk
                         { enterDetail = SyscallEnterDetails_brk{ addr }, brkResult })
                ) <- events
              ]
        brkCallAddresses `shouldSatisfy` ((3 <=) . length)
        let (initArg, initAddr) = brkCallAddresses !! (length brkCallAddresses - 3)
        let extAddr = plusPtr initAddr (0x80 * sizeOf initAddr)
        initArg `shouldBe` nullPtr
        elem (extAddr, extAddr) brkCallAddresses `shouldBe` True
        elem (initAddr, initAddr) brkCallAddresses `shouldBe` True

    describe "symlink" $ do
      it "seen exactly once for 'ln -s tempfile tempfilesymlink'" $ do
        tmpFile <- emptySystemTempFile "test-output"
        let symlinkPath = tmpFile ++ "symlink"
        argv <- procToArgv "bash" ["-c", "ln -s " ++ tmpFile ++ " " ++ symlinkPath]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        -- it was observed that on different distros 'ln -s' could use either
        -- symlink or symlinkat
        let maybeSymlinkPath exitDetails = case exitDetails of
              DetailedSyscallExit_symlink
                SyscallExitDetails_symlink
                { enterDetail = SyscallEnterDetails_symlink{ linkpathBS }} ->
                Just linkpathBS
              DetailedSyscallExit_symlinkat
                SyscallExitDetails_symlinkat
                { enterDetail = SyscallEnterDetails_symlinkat{ linkpathBS }} ->
                Just linkpathBS
              _ ->
                Nothing
            symlinkEvents =
              [ exitDetails
              | (_pid, Right exitDetails) <- events
              , fromMaybe False $ do
                  linkpathBS <- maybeSymlinkPath exitDetails
                  return $ linkpathBS == T.encodeUtf8 (T.pack symlinkPath)
              ]
        length symlinkEvents `shouldBe` 1

    describe "symlinkat" $ do
      it "seen exactly once for './symlinkat" $ do
        callProcess "make" ["--quiet", "example-programs-build/symlinkat"]
        tmpFile <- emptySystemTempFile "test-output"
        let symlinkPath = tmpFile ++ "symlink"
        argv <- procToArgv "example-programs-build/symlinkat" [tmpFile, symlinkPath]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let symlinkEvents =
              [ linkpathBS
              | (_pid
                , Right (DetailedSyscallExit_symlinkat
                         SyscallExitDetails_symlinkat
                         { enterDetail = SyscallEnterDetails_symlinkat{ linkpathBS }})
                ) <- events
                , linkpathBS == T.encodeUtf8 (T.pack symlinkPath)
              ]
        length symlinkEvents `shouldBe` 1

    describe "poll" $ do
      it "detects correctly all events" $ do
        let pollCall = "example-programs-build/poll"
        callProcess "make" ["--quiet", pollCall]
        tmpFile <- emptySystemTempFile "temp-file"
        argv <- procToArgv pollCall [tmpFile]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let pollResult = [ (nfds, fdsValue)
                         | (_pid
                           , Right (DetailedSyscallExit_poll
                                    SyscallExitDetails_poll
                                    { enterDetail = SyscallEnterDetails_poll{ nfds }, fdsValue })
                           ) <- events
                         ]
        length pollResult `shouldBe` 1
        let (nfds, fdsValue) = head pollResult
        length fdsValue `shouldBe` 3
#ifdef USE_POLL_POLLRDHUP
        System.Hatrace.Types.events (head fdsValue) `shouldSatisfy` ( \case
                                                  PollEventsKnown gpe -> pollrdhup gpe
                                                  _ -> False
                                              )
#endif
        nfds `shouldBe` 3

#ifdef USE_POLLING_WITH_SIGMASK
    describe "ppoll" $ do
      it "detects correctly all events and sigmask" $ do
        let pollCall = "example-programs-build/ppoll"
        callProcess "make" ["--quiet", pollCall]
        tmpFile <- emptySystemTempFile "temp-file"
        argv <- procToArgv pollCall [tmpFile]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallEnterDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let pollResult = [ (fdsValue, sigmaskValue)
                         | (_pid
                           , DetailedSyscallEnter_ppoll
                               SyscallEnterDetails_ppoll{ fdsValue, sigmaskValue }
                           ) <- events
                         ]
        length pollResult `shouldBe` 1
        let (fdsValue, SigSet sigmask) = head pollResult
        length fdsValue `shouldBe` 3
        sigmask `shouldContain` [sigINT, sigQUIT, sigKILL, sigUSR1, sigSYS]
#endif

    describe "arch_prctl" $ do
      it "seen ARCH_GET_FS used by example executable" $ do
        callProcess "make" ["--quiet", "example-programs-build/get-fs"]
        argv <- procToArgv "example-programs-build/get-fs" []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let subfunctions =
              [ subfunction enterDetail
              | (_pid
                , Right (DetailedSyscallExit_arch_prctl
                         SyscallExitDetails_arch_prctl
                         { enterDetail })
                ) <- events
              ]
        subfunctions `shouldSatisfy` (ArchGetFs `elem`)

    describe "set_tid_address" $ do
      it "seen set_tid_address used by example executable" $ do
        let progName = "example-programs-build/set-tid-address"
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let sets =
              [ tidptr enterDetail
              | (_pid
                , Right (DetailedSyscallExit_set_tid_address
                         SyscallExitDetails_set_tid_address
                         { enterDetail })
                ) <- events
              ]
        sets `shouldSatisfy` (not . null)

    describe "sysinfo" $ do
      it "seen sysinfo used by example executable" $ do
        let progName = "example-programs-build/sysinfo-loads"
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let sysinfoDetails =
              [ enterDetail
              | (_pid
                , Right (DetailedSyscallExit_sysinfo
                         SyscallExitDetails_sysinfo
                         { enterDetail })
                ) <- events
              ]
        length sysinfoDetails `shouldBe` 1

    describe "madvise" $ do
      it "seen madvise used by example executable" $ do
        let progName = "example-programs-build/madvise"
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let memAdvices =
              [ memAdvice
              | (_pid
                , Right (DetailedSyscallExit_madvise
                         SyscallExitDetails_madvise
                         { enterDetail = SyscallEnterDetails_madvise { memAdvice } })
                ) <- events
              ]
        memAdvices `shouldBe` [ MemAdviceKnown MadvRandom ]

    describe "mprotect" $ do
      it "seen mprotect used by example executable" $ do
        let progName = "example-programs-build/mprotect"
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let readAccess = noAccess { accessProtectionRead = True }
            mprotects =
              [ protection
              | (_pid
                , Right (DetailedSyscallExit_mprotect
                         SyscallExitDetails_mprotect
                         { enterDetail = SyscallEnterDetails_mprotect { protection } })
                ) <- events
              , protection == AccessProtectionKnown readAccess
              ]
        length mprotects `shouldBe` 1

    describe "sched_yield" $ do
      it "seen sched_yield used by example executable" $ do
        let progName = "example-programs-build/sched_yield"
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let sched_yields =
              [ details
              | (_pid
                , Right (DetailedSyscallExit_sched_yield details)
                ) <- events
              ]
        length sched_yields `shouldBe` 1

    describe "kill" $ do
      it "seen kill used by example executable" $ do
        let progName = "example-programs-build/kill"
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let kills =
              [ sig
              | (_pid
                , Right (DetailedSyscallExit_kill
                         SyscallExitDetails_kill
                         { enterDetail = SyscallEnterDetails_kill { sig } })
                ) <- events
              , sig == sigUSR1
              ]
        length kills `shouldBe` 1

    describe "getuid" $ do
      it "should return the current user id" $ do
        let progName = "example-programs-build/user-infos"
        userId <- getRealUserID
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let getuid_details =
              [ syscallUserId
              | (_pid
                , Right (DetailedSyscallExit_getuid
                         SyscallExitDetails_getuid
                         { userId = syscallUserId })
                ) <- events
              ]
        getuid_details `shouldBe` [fromIntegral userId]

    describe "getgid" $ do
      it "should return the current group id" $ do
        let progName = "example-programs-build/user-infos"
        groupId <- getRealGroupID
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let getgid_details =
              [ syscallGroupId
              | (_pid
                , Right (DetailedSyscallExit_getgid
                         SyscallExitDetails_getgid
                         { groupId = syscallGroupId })
                ) <- events
              ]
        getgid_details `shouldBe` [fromIntegral groupId]

    describe "geteuid" $ do
      it "should return the current effective user id" $ do
        let progName = "example-programs-build/user-infos"
        userId <- getEffectiveUserID
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let geteuid_details =
              [ syscallUserId
              | (_pid
                , Right (DetailedSyscallExit_geteuid
                         SyscallExitDetails_geteuid
                         { userId = syscallUserId })
                ) <- events
              ]
        geteuid_details `shouldBe` [fromIntegral userId]

    describe "getegid" $ do
      it "should return the current effective group id" $ do
        let progName = "example-programs-build/user-infos"
        groupId <- getEffectiveGroupID
        callProcess "make" ["--quiet", progName]
        argv <- procToArgv progName []
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let getegid_details =
              [ syscallGroupId
              | (_pid
                , Right (DetailedSyscallExit_getegid
                         SyscallExitDetails_getegid
                         { groupId = syscallGroupId })
                ) <- events
              ]
        getegid_details `shouldBe` [fromIntegral groupId]

    describe "clone" $ do
      it "seen clone from a shell command group" $ do
        argv <- procToArgv "sh" ["-c", "(echo 42 > /dev/null)"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let clones =
              [ termSignal
              | (_pid
                , Right (DetailedSyscallExit_clone
                         SyscallExitDetails_clone
                         { enterDetail = SyscallEnterDetails_clone { termSignal } })
                ) <- events
              , termSignal == sigCHLD
              ]
        length clones `shouldBe` 1

    describe "prlimit64" $ do
      it "seen prlimit64 from a shell command ulimit" $ do
        argv <- procToArgv "sh" ["-c", "ulimit -n > /dev/null"]
        (exitCode, events) <-
          sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let prlimits =
              [ termSignal
              | (_pid
                , Right (DetailedSyscallExit_prlimit64
                         SyscallExitDetails_prlimit64
                         { enterDetail = SyscallEnterDetails_prlimit64 { rlimitType } })
                ) <- events
              , rlimitType == ResourceTypeKnown ResourceNoFile
              ]
        length prlimits `shouldBe` 1

    describe "chdir" $ do
      it "occurs when we change the current directory" $ do
        let testProgram = "example-programs-build/chdir"
        callProcess "make" ["--quiet", testProgram]
        let tmpDirectory = "/tmp"
        argv <- procToArgv testProgram [tmpDirectory]
        (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv $
          syscallExitDetailsOnlyConduit .| CL.consume
        exitCode `shouldBe` ExitSuccess
        let directories =
              [ pathBS
              | (_pid
                , Right (DetailedSyscallExit_chdir
                         SyscallExitDetails_chdir
                         { enterDetail = SyscallEnterDetails_chdir { pathBS } })
                ) <- events
              ]
        directories `shouldBe` [T.encodeUtf8 (T.pack tmpDirectory)]

    describe "mkdir" $ do
      it "occurs when we create a directory" $ do
        withSystemTempDirectory "hatrace-test-mkdir" $ \tmpDirectory -> do
          let directoryToMk = tmpDirectory <> "/mkdir-test"
          print directoryToMk
          let testProgram = "example-programs-build/mkdir"
          callProcess "make" ["--quiet", testProgram]
          argv <- procToArgv testProgram [directoryToMk]
          (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
          exitCode `shouldBe` ExitSuccess
          let directories =
                [ pathnameBS
                | (_pid
                  , Right (DetailedSyscallExit_mkdir
                           SyscallExitDetails_mkdir
                           { enterDetail = SyscallEnterDetails_mkdir { pathnameBS } })
                  ) <- events
                ]
          directories `shouldBe` [T.encodeUtf8 (T.pack directoryToMk)]

    describe "rmdir" $ do
      it "occurs when we delete a directory" $ do
        withSystemTempDirectory "hatrace-test-rmdir" $ \directoryToRm -> do
          let testProgram = "example-programs-build/rmdir"
          callProcess "make" ["--quiet", testProgram]
          argv <- procToArgv testProgram [directoryToRm]
          (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv $
            syscallExitDetailsOnlyConduit .| CL.consume
          exitCode `shouldBe` ExitSuccess
          let directories =
                [ pathnameBS
                | (_pid
                  , Right (DetailedSyscallExit_rmdir
                           SyscallExitDetails_rmdir
                           { enterDetail = SyscallEnterDetails_rmdir { pathnameBS } })
                  ) <- events
                ]
          directories `shouldBe` [T.encodeUtf8 (T.pack directoryToRm)]

