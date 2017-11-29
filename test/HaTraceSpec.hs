module HaTraceSpec where

import Test.Hspec

import HaTrace

spec :: Spec
spec =
    describe "traceCreateProcess" $ do
    it "does not crash for this echo process" $
        traceCreateProcess (shell "echo hello") `shouldReturn` ExitSuccess
    it "does not crash for this sleep process" $
        traceCreateProcess (shell "sleep 1") `shouldReturn` ExitSuccess
