module HaTraceSpec where

import           System.Exit
import           System.Process (callProcess)
import           Test.Hspec

import HaTrace

spec :: Spec
spec =
  describe "traceCreateProcess" $ do

    it "does not crash for this echo process" $ do
      traceForkProcess "echo" ["hello"] `shouldReturn` ExitSuccess

    it "does not crash for this sleep process" $ do
      traceForkProcess "sleep" ["1"] `shouldReturn` ExitSuccess

    -- TODO Instead of compiling things here with `make`, do it as a Cabal hook.

    it "does not crash for hello.asm with 32-bit API" $ do
      callProcess "make" ["--quiet", "example-programs/hello-linux-i386-elf64"]
      traceForkProcess "example-programs/hello-linux-i386-elf64" [] `shouldReturn` ExitSuccess

    it "does not crash for hello.asm with 64-bit API" $ do
      callProcess "make" ["--quiet", "example-programs/hello-linux-x86_64"]
      traceForkProcess "example-programs/hello-linux-x86_64" [] `shouldReturn` ExitSuccess

    it "does not hang when the traced program segfaults" $ do
      callProcess "make" ["--quiet", "example-programs/segfault"]
      traceForkProcess "example-programs/segfault" [] `shouldReturn` ExitFailure 139
