 import           Test.Hspec.Formatters.Jenkins (xmlFormatter)
 import           Test.Hspec.Runner


 main :: IO ()
 main = do
   summary <- withFile "results.xml" WriteMode $ \h -> do
      let config = defaultConfig
            { configFormatter = xmlFormatter
            , configHandle = h
            }
      hspecWith config spec

   unless (summaryFailures summary == 0) $
     exitFailure
