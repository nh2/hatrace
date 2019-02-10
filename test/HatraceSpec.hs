module HatraceSpec where

import           Data.Conduit
import qualified Data.Conduit.List as CL
import           System.Exit
import           System.Process (callProcess)
import           Test.Hspec

import System.Hatrace

spec :: Spec
spec = do
  describe "traceCreateProcess" $ do

    it "does not crash for this echo process" $ do
      traceForkProcess "echo" ["hello"] `shouldReturn` ExitSuccess

    it "does not crash for this sleep process" $ do
      traceForkProcess "sleep" ["1"] `shouldReturn` ExitSuccess

    -- TODO Instead of compiling things here with `make`, do it as a Cabal hook.

    it "does not crash for hello.asm with 32-bit API" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-i386-elf64"]
      traceForkProcess "example-programs-build/hello-linux-i386-elf64" [] `shouldReturn` ExitSuccess

    it "does not crash for hello.asm with 64-bit API" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
      traceForkProcess "example-programs-build/hello-linux-x86_64" [] `shouldReturn` ExitSuccess

    it "does not hang when the traced program segfaults" $ do
      callProcess "make" ["--quiet", "example-programs-build/segfault"]
      traceForkProcess "example-programs-build/segfault" [] `shouldReturn` ExitFailure 139

  describe "sourceTraceForkExecvFullPathWithSink" $ do

    it "lets the process finish if the sink exits early" $ do
      argv <- procToArgv "echo" ["hello"]
      (exitCode, ()) <- runConduit $ sourceTraceForkExecvFullPathWithSink argv (return ())
      exitCode `shouldBe` ExitSuccess

    it "allows obtaining all syscalls as a list for hello.asm" $ do
      callProcess "make" ["--quiet", "example-programs-build/hello-linux-x86_64"]
      argv <- procToArgv "example-programs-build/hello-linux-x86_64" []
      (exitCode, syscallDetails) <- runConduit $ sourceTraceForkExecvFullPathWithSink argv CL.consume

      let syscalls = [ syscall | (_pid, SyscallStop (SyscallEnter (syscall, _args))) <- syscallDetails ]
      exitCode `shouldBe` ExitSuccess
      syscalls `shouldBe`
        [ KnownSyscall Syscall_execve
        , KnownSyscall Syscall_write
        , KnownSyscall Syscall_exit
        ]
