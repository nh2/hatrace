{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module System.Hatrace.Types.TH
  ( deriveCIntRepresentable
  , deriveArgFormatting
  , deriveFlagsTypeClasses
  ) where

import Data.List (isSuffixOf,  partition)
import Foreign.C.Types (CInt(..))
import Language.Haskell.TH
import Language.Haskell.TH.Datatype
import Language.Haskell.TH.Syntax
import System.Hatrace.Types.Internal
import System.Hatrace.Format

-- | derives an instance of CIntRepresentable for a datatype
-- which is supposed to have a shape like
--
-- @
-- data X = XKnown GranularX | XUnknown CInt
-- @
--
-- with a type GranularX like
--
-- @
-- data GranularX = GranularX
--   { flagA :: Bool
--   , flagB :: Bool
--   }
-- @
--
-- for such a type one could use
--
-- @
-- \$(deriveCIntRepresentable ''X
--   [ 'flagA, (#const FLAG_A)
--   , 'flagB, (#const FLAG_B)
--   ]
-- @
--
-- to produce a definition like
--
-- @
-- instance CIntRepresentable X where
-- toCInt (XKnown x) =
--    (if flagA x then (#const FLAG_A) else 0) .|.
--    (if flagB x then (#const FLAG_B) else 0) .|.
--    0
-- toCInt (XUnknown x) = x
-- fromCInt x | (x .&. complement knownBits) /= zeroBits = XUnknown x
--            | otherwise =
--               XKnown GranularX
--                 { flagA = x `hasSetBits` (#const FLAG_A)
--                 , flagB = x `hasSetBits` (#const FLAG_B)
--                 }
--   where
--     knownBits = (#const FLAG_A) .|. (#const FLAG_B)
-- @
deriveCIntRepresentable :: Name -> [(Name, Int)] -> Q [Dec]
deriveCIntRepresentable typeName fieldFlags = do
  dt <- reifyDatatype typeName
  flagTypes <- splitConstructors typeName (datatypeCons dt)
  (:[]) <$> deriveCIntRepresentable' flagTypes fieldFlags

deriveCIntRepresentable' :: FlagTypes -> [(Name, Int)] -> Q Dec
deriveCIntRepresentable' flagTypes fieldFlags = do
  let FlagTypes{typeName, known, unknown, granular} = flagTypes
  x <- newName "x"
  let oredFields = foldr1 orE $ map fieldValE fieldFlags
      fieldValE :: (Name, Int) -> ExpQ
      fieldValE (field, v) = [| (if $(appE (varE field) (varE x)) then v else 0) |]
      orE v1 v2 = [| $v1 .|. $v2 |]
      toCIntImpl =
        funD 'toCInt [ clause [conP known [varP x]] (normalB oredFields) []
                     , clause [conP unknown [varP x]] (normalB (varE x)) []
                     ]
      knownBits = foldr1 orE $ [ [| v  |]| (_, v) <- fieldFlags]
      granularFields :: [Q (Name, Exp)]
      granularFields =
        [ (field,) <$> [| $(varE x) `hasSetBits` v |] | (field, v) <- fieldFlags]
      fromCIntBody =
        [| if ($(varE x) .&. complement $knownBits) /= zeroBits
           then $(conE unknown) $(varE x)
           else $(conE known) $(recConE granular granularFields)
        |]
      fromCIntImpl =
        funD 'fromCInt [ clause [varP x] (normalB fromCIntBody) []
                       ]
      methods = [toCIntImpl, fromCIntImpl]
  instanceD (cxt []) (appT (conT ''CIntRepresentable) (conT typeName)) methods

-- | derives an instance of ArgFormatting for a datatype
-- which is supposed to have a shape like
--
-- @
-- data X = XKnown GranularX | XUnknown CInt
-- @
--
-- with a type GranularX like
--
-- @
-- data GranularX = GranularX
--   { flagA :: Bool
--   , flagB :: Bool
--   }
-- @
--
-- for such a type one could use
--
-- @
-- \$(deriveArgFormatting ''X "FLAG_NONE"
--   [ ('flagA, "FLAG_A")
--   , ('flagB, "FLAG_B")
--   ]
-- @
--
-- to produce a definition like
--
-- @
-- instance ArgFormatting X where
--   formatArg =  FixedStringArg . formatFlags
--     where
--       formatFlags (XKnown flags) =
--         let granularFlags = concat
--               [ if flagA flags then ["FLAG_A"] else []
--               , if flagB flags then ["FLAG_B"] else []
--               ]
--         in if null granularFlags then "FLAG_NONE" else intercalate "|" granularFlags
--       formatFlags (XUnknown x) = show x
-- @
deriveArgFormatting :: Name -> String -> [(Name, String)] -> Q [Dec]
deriveArgFormatting typeName def fieldFlags = do
  dt <- reifyDatatype typeName
  flagTypes <- splitConstructors typeName (datatypeCons dt)
  (:[]) <$> deriveArgFormatting' flagTypes def fieldFlags

deriveArgFormatting' :: FlagTypes -> String -> [(Name, String)] -> Q Dec
deriveArgFormatting' flagTypes def fieldFlags = do
  let FlagTypes{typeName, known, unknown } = flagTypes
  x <- newName "x"
  let
    formatArgImpl :: DecQ
    formatArgImpl =
      valD
        (varP 'formatArg)
        (normalB [| FixedStringArg . $formatFlags |])
        []
    concatE :: [ExpQ] -> ExpQ
    concatE xs = [| concat $(listE xs) |]
    granularFlags :: ExpQ
    granularFlags = concatE [ [| if $(appE (varE field) (varE x)) then [str] else [] |]
                            | (field, str) <- fieldFlags ]
    formatFlags =
      [| \f ->
          case f of
            $(conP known [varP x]) ->
              if null $granularFlags then def else intercalate "|" $granularFlags
            $(conP unknown [varP x]) -> show $(varE x)
       |]
  instanceD (cxt []) (appT (conT ''ArgFormatting) (conT typeName)) [formatArgImpl]

-- | a combination of deriveCIntRepresentable and deriveArgFormatting:
-- generates 2 type classes using call
deriveFlagsTypeClasses :: Name -> String -> [(Name, Int, String)] -> Q [Dec]
deriveFlagsTypeClasses typeName def fieldFlags = do
  dt <- reifyDatatype typeName
  flagTypes <- splitConstructors typeName (datatypeCons dt)
  let flagValues = [ (field, v) | (field, v, _) <- fieldFlags ]
  cIntRepresentable <- deriveCIntRepresentable' flagTypes flagValues
  let flagNames = [ (field, n) | (field, _, n) <- fieldFlags ]
  argFormatting <- deriveArgFormatting' flagTypes def flagNames
  pure [cIntRepresentable, argFormatting]

data FlagTypes = FlagTypes
  { typeName :: Name
  , known :: Name
  , unknown :: Name
  , granular :: Name
  }

splitConstructors :: Name -> [ConstructorInfo] -> Q FlagTypes
splitConstructors typeName cs = do
  cint <- datatypeType <$> reifyDatatype ''CInt
  case partition isKnown cs of
    ([k], [u]) | isUnknown cint u, [ConT granularType] <- constructorFields k -> do
                   [g] <- datatypeCons <$> reifyDatatype granularType
                   pure FlagTypes
                     { typeName = typeName
                     , known = constructorName k
                     , unknown = constructorName u
                     , granular = constructorName g
                     }
    _ ->
      fail "Datatype must have 2 constructors: 1 for known values and 1 for unknown(unexpected) values"

isKnown :: ConstructorInfo -> Bool
isKnown c =
  constructorVars c == [] &&
  length (constructorFields c) == 1 &&
  nameHasSuffix "Known" (constructorName c)

isUnknown :: Type -> ConstructorInfo -> Bool
isUnknown cint c =
  constructorVars c == [] &&
  constructorFields c == [cint] &&
  nameHasSuffix "Unknown" (constructorName c)

nameHasSuffix :: String -> Name -> Bool
nameHasSuffix s name =
  case name of
    Name occName (NameG _ _ _) -> s `isSuffixOf` occString occName
    _ -> False
