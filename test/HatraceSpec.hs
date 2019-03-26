{-# LANGUAGE DuplicateRecordFields #-}
{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE OverloadedStrings #-}
{-# LANGUAGE ScopedTypeVariables #-}

module HatraceSpec where

import           Control.Monad (when)
import           Control.Monad.IO.Class (liftIO)
import           Control.Monad.IO.Unlift (MonadUnliftIO)
import qualified Data.ByteString as BS
import           Data.Conduit
import qualified Data.Conduit.Combinators as CC
import qualified Data.Conduit.List as CL
import           Data.Set (Set)
import qualified Data.Set as Set
import qualified Data.Text as T
import qualified Data.Text.Encoding as T
import           Foreign.C.Error (eBADF)
import           System.FilePath (takeFileName, takeDirectory)
import           System.Directory (doesFileExist, removeFile)
import           System.Exit
import           System.IO.Temp (emptySystemTempFile)
import           System.Posix.Files (getFileStatus, fileSize, readSymbolicLink)
import           System.Posix.Resource (Resource(..), ResourceLimit(..), ResourceLimits(..), getResourceLimit, setResourceLimit)
import           System.Posix.Signals (sigTERM)
import           System.Process (callProcess, readProcess)
import           Test.Hspec
import           Text.Read (readMaybe)
import           UnliftIO.Exception (bracket)

import System.Hatrace


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

  describe "traceCreateProcess" $ do

    it "does not crash for this echo process" $ do
      traceForkProcess "echo" ["hello"] `shouldReturn` ExitSuccess

    -- TODO Instead of compiling things here with `make`, do it as a Cabal hook.

    it "does not crash for hello.asm with 32-bit API" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-i386-elf64"]
      traceForkProcess "example-programs-build/hello-linux-i386-elf64" [] `shouldReturn` ExitSuccess

    it "does not crash for hello.asm real 32-bit" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-i386"]
      traceForkProcess "example-programs-build/hello-linux-i386" [] `shouldReturn` ExitSuccess

    it "does not crash for hello.asm with 64-bit API" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
      traceForkProcess "example-programs-build/hello-linux-x86_64" [] `shouldReturn` ExitSuccess

    it "does not hang when the traced program segfaults" $ do
      callProcess "make" ["--quiet", "example-programs-build/segfault"]
      -- Disable core dumps for the test to not litter in the working tree.
      withCoredumpsDisabled $ do
        -- Note: When we don't disable coredumps, the exit code is 139 instead.
        -- 11 is certainly signal SIGSEGV, but I'm not sure what exactly the
        -- added 128 indicate (is that how the kernel tells us whether or not
        -- "core dumped" happened?).
        -- See also https://github.com/nh2/hatrace/issues/4#issuecomment-475196313
        traceForkProcess "example-programs-build/segfault" [] `shouldReturn` ExitFailure 11

  describe "sourceTraceForkExecvFullPathWithSink" $ do

    it "lets the process finish if the sink exits early" $ do
      argv <- procToArgv "echo" ["hello"]
      (exitCode, ()) <- sourceTraceForkExecvFullPathWithSink argv (return ())
      exitCode `shouldBe` ExitSuccess

    it "allows obtaining all syscalls as a list for hello.asm" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
      argv <- procToArgv "example-programs-build/hello-linux-x86_64" []
      (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv CL.consume

      let syscalls = [ syscall | (_pid, SyscallStop (SyscallEnter (syscall, _args))) <- events ]
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
        sourceTraceForkExecvFullPathWithSink argv $
          syscallExitDetailsOnlyConduit .| CL.consume
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
        (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv CL.consume
        let cloneWriteSyscalls =
              [ syscall
              | (_pid, SyscallStop (SyscallEnter (KnownSyscall syscall, _args))) <- events
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
            (exitCode, events) <- sourceTraceForkExecvFullPathWithSink argv CL.consume
            let syscalls = [ syscall | (_pid, SyscallStop (SyscallEnter (syscall, _args))) <- events ]
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

            let isWrite (_pid, SyscallStop (SyscallEnter (KnownSyscall Syscall_write, _args))) = True
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

            _ <- sourceTraceForkExecvFullPathWithSink argv killAt4thWriteConduit

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
      -- let ghc = "/raid/src/ghc/ghc-atomic-writes/_build/stage1/bin/ghc"
      -- So that a custom path can be given conveniently when testing a patch.
      -- You probably want to set GHC_PACKAGE_PATH below when doing that so that
      -- your custom GHC works even under `stack test`.
      let isPatchedGhc = ghc /= "ghc"
      let args =
            [ ghc
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
                      -> (major, minor) <= (8,6)
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

    describe "execve" $ do

      let runExecveProgram :: FilePath -> FilePath -> IO (ExitCode, [SyscallExitDetails_execve])
          runExecveProgram execveProgram programToExecve = do
            innerArgv <- procToArgv programToExecve []
            argv <- procToArgv execveProgram innerArgv
            (exitCode, events) <-
              sourceTraceForkExecvFullPathWithSink argv $
                syscallExitDetailsOnlyConduit .| CL.consume
            let execveDetails =
                  [ detail
                  | (_pid, Right (DetailedSyscallExit_execve detail)) <- events
                  ]
            return (exitCode, execveDetails)

      it "shows the right execve results for './execve hello-linux-x86_64'" $ do

        callProcess "make" ["--quiet", "example-programs-build/execve", "example-programs-build/hello-linux-x86_64"]
        (exitCode, execveDetails) <-
          runExecveProgram
            "example-programs-build/execve"
            "example-programs-build/hello-linux-x86_64"
        exitCode `shouldBe` ExitSuccess
        -- There should be one execve() for our C program being started by the
        -- test process, and one by the program that it execve()s.
        execveDetails `shouldBe`
          [ SyscallExitDetails_execve {optionalEnterDetail = Nothing, execveResult = 0}
          , SyscallExitDetails_execve {optionalEnterDetail = Nothing, execveResult = 0}
          ]

      it "shows the right execve results for the special case './execve-linux-null-envp hello-linux-x86_64'" $ do

        callProcess "make" ["--quiet", "example-programs-build/execve-linux-null-envp", "example-programs-build/hello-linux-x86_64"]
        (exitCode, execveDetails) <-
          runExecveProgram
            "example-programs-build/execve-linux-null-envp"
            "example-programs-build/hello-linux-x86_64"
        exitCode `shouldBe` ExitSuccess
        -- There should be one execve() for our C program being started by the
        -- test process, and one by the program that it execve()s.
        execveDetails `shouldBe`
          [ SyscallExitDetails_execve {optionalEnterDetail = Nothing, execveResult = 0}
          , SyscallExitDetails_execve {optionalEnterDetail = Nothing, execveResult = 0}
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
        let tmpFileOpenatEvents =
              [ pathnameBS
              | (_pid
                , Right (DetailedSyscallExit_openat
                         SyscallExitDetails_openat
                         { enterDetail = SyscallEnterDetails_openat{ pathnameBS }})
                ) <- events
                , pathnameBS == T.encodeUtf8 (T.pack tmpFile)
              ]
        tmpFileOpenatEvents `shouldSatisfy` (not . null)
