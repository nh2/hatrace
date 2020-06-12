{-# LANGUAGE NamedFieldPuns #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE TupleSections #-}

module System.Hatrace.Types.TH
  ( deriveFlagsCIntRepresentable
  , deriveFlagsArgFormatting
  , deriveFlagsTypeClasses
  , deriveEnumCIntRepresentable
  , deriveEnumArgFormatting
  , deriveEnumTypeClasses
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
-- \$(deriveFlagsCIntRepresentable ''X
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
deriveFlagsCIntRepresentable :: Name -> [(Name, Int)] -> Q [Dec]
deriveFlagsCIntRepresentable typeName fieldFlags = do
  dt <- reifyDatatype typeName
  types <- splitConstructors typeName (datatypeCons dt) getGranularConstructor
  (:[]) <$> deriveFlagsCIntRepresentable' types fieldFlags

deriveFlagsCIntRepresentable' :: TypeDetails Name -> [(Name, Int)] -> Q Dec
deriveFlagsCIntRepresentable' types fieldFlags = do
  let TypeDetails{typeName, known, unknown, granular} = types
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
-- \$(deriveFlagsArgFormatting ''X "FLAG_NONE"
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
deriveFlagsArgFormatting :: Name -> String -> [(Name, String)] -> Q [Dec]
deriveFlagsArgFormatting typeName def fieldFlags = do
  dt <- reifyDatatype typeName
  types <- splitConstructors typeName (datatypeCons dt) getGranularConstructor
  (:[]) <$> deriveFlagsArgFormatting' types def fieldFlags

deriveFlagsArgFormatting' :: TypeDetails Name -> String -> [(Name, String)] -> Q Dec
deriveFlagsArgFormatting' types def fieldFlags = do
  let TypeDetails{typeName, known, unknown } = types
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

-- | a combination of deriveFlagsCIntRepresentable and deriveFlagsArgFormatting:
-- generates 2 type classes using 1 call
deriveFlagsTypeClasses :: Name -> String -> [(Name, Int, String)] -> Q [Dec]
deriveFlagsTypeClasses typeName def fieldFlags = do
  dt <- reifyDatatype typeName
  types <- splitConstructors typeName (datatypeCons dt) getGranularConstructor
  let flagValues = [ (field, v) | (field, v, _) <- fieldFlags ]
  cIntRepresentable <- deriveFlagsCIntRepresentable' types flagValues
  let flagNames = [ (field, n) | (field, _, n) <- fieldFlags ]
  argFormatting <- deriveFlagsArgFormatting' types def flagNames
  pure [cIntRepresentable, argFormatting]

data TypeDetails a = TypeDetails
  { typeName :: Name
  , known :: Name
  , unknown :: Name
  , granular :: a
  }

-- | a combination of deriveEnumCIntRepresentable and deriveEnumArgFormatting:
-- generates 2 type classes using 1 call
deriveEnumTypeClasses :: Name -> [(Name, Int, String)] -> Q [Dec]
deriveEnumTypeClasses typeName enumOpts = do
  dt <- reifyDatatype typeName
  types <- splitConstructors typeName (datatypeCons dt) (\_ -> pure ())
  let enumValues = [ (enumVal, v) | (enumVal, v, _) <- enumOpts ]
  cIntRepresentable <- deriveEnumCIntRepresentable' types enumValues
  let enumNames = [ (enumVal, n) | (enumVal, _, n) <- enumOpts ]
  argFormatting <- deriveEnumArgFormatting' types enumNames
  pure [cIntRepresentable, argFormatting]

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
-- data GranularX
--   = GranularA
--   | GranularB
-- @
--
-- for such a type one could use
--
-- @
-- \$(deriveEnumArgFormatting ''X
--   [ ('GranularA, "X_A")
--   , ('GranularB, "X_B")
--   ]
-- @
--
-- to produce a definition like
--
-- @
-- instance ArgFormatting X where
--   formatArg (XKnown known) = FixedStringArg $ case known of
--     GranularA -> "X_A"
--     GranularB -> "X_B"
--   formatArg (XUnknown unknown) = IntegerArg (fromIntegral unknown)
-- @
deriveEnumArgFormatting :: Name -> [(Name, String)] -> Q [Dec]
deriveEnumArgFormatting typeName enumFlags = do
  dt <- reifyDatatype typeName
  types <- splitConstructors typeName (datatypeCons dt) (\_ -> pure ())
  (:[]) <$> deriveEnumArgFormatting' types enumFlags

deriveEnumArgFormatting' :: TypeDetails () -> [(Name, String)] -> Q Dec
deriveEnumArgFormatting' types enums = do
  let TypeDetails{typeName, known, unknown } = types
  x <- newName "x"
  let
    formatArgImpl :: DecQ
    formatArgImpl =
      valD
        (varP 'formatArg)
        (normalB
          [| \f ->
              case f of
                $(conP known [varP x]) -> FixedStringArg $enumVal
                $(conP unknown [varP x]) ->
                  IntegerArg (fromIntegral $(varE x))
           |])
        []
    enumVal :: ExpQ
    enumVal = caseE (varE x)
      [ match (conP field []) (normalB (litE (stringL str))) []
      | (field, str) <- enums ]
  instanceD (cxt []) (appT (conT ''ArgFormatting) (conT typeName)) [formatArgImpl]

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
-- data GranularX
--   = GranularA
--   | GranularB
-- @
--
-- for such a type one could use
--
-- @
-- \$(deriveEnumCIntRepresentable ''X
--   [ 'GranularA, (#const X_A)
--   , 'GranularB, (#const X_B)
--   ]
-- @
--
-- to produce a definition like
--
-- @
-- instance CIntRepresentable X where
-- toCInt (XKnown known) =
--    case known of
--      GranularA -> (#const X_A)
--      GranularB -> (#const X_B)
-- toCInt (XUnknown x) = x
-- fromCInt x =
--   case x of
--     (#const X_A) -> XKnown GranularA
--     (#const X_B) -> XKnown GranularB
--     uknown -> XUnknown unknown
-- @
deriveEnumCIntRepresentable :: Name -> [(Name, Int)] -> Q [Dec]
deriveEnumCIntRepresentable typeName enumFlags = do
  dt <- reifyDatatype typeName
  types <- splitConstructors typeName (datatypeCons dt) (\_ -> pure ())
  (:[]) <$> deriveEnumCIntRepresentable' types enumFlags

deriveEnumCIntRepresentable' :: TypeDetails () -> [(Name, Int)] -> Q Dec
deriveEnumCIntRepresentable' types enums = do
  let TypeDetails{typeName, known, unknown} = types
  x <- newName "x"
  y <- newName "y"
  let enum2Int = caseE (varE x)
        [ match (conP enum []) (normalB (litE (integerL (toInteger i)))) []
        | (enum, i) <- enums ]
      toCIntImpl =
        funD 'toCInt [ clause [conP known [varP x]] (normalB enum2Int) []
                     , clause [conP unknown [varP x]] (normalB (varE x)) []
                     ]
      fromCIntBody = caseE (varE x) $
        [ match (litP (integerL (toInteger i)))
                (normalB [| $(conE known) $(conE enum) |]) []
        | (enum, i) <- enums ]
        ++
        [ match (varP y) (normalB [| $(conE unknown) $(varE y) |]) [] ]
      fromCIntImpl =
        funD 'fromCInt [ clause [varP x] (normalB fromCIntBody) []
                       ]
      methods = [toCIntImpl, fromCIntImpl]
  instanceD (cxt []) (appT (conT ''CIntRepresentable) (conT typeName)) methods

splitConstructors :: Name -> [ConstructorInfo] -> (Name -> Q a) -> Q (TypeDetails a)
splitConstructors typeName cs extractGranular = do
  cint <- datatypeType <$> reifyDatatype ''CInt
  case partition isKnown cs of
    ([k], [u]) | isUnknown cint u, [ConT granularType] <- constructorFields k -> do
                   granular <- extractGranular granularType
                   pure TypeDetails
                     { typeName = typeName
                     , known = constructorName k
                     , unknown = constructorName u
                     , granular = granular
                     }
    _ ->
      fail "Datatype must have 2 constructors: 1 for known values and 1 for unknown(unexpected) values"

getGranularConstructor :: Name -> Q Name
getGranularConstructor t = do
  [g] <- datatypeCons <$> reifyDatatype t
  pure (constructorName g)

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
