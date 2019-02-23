{-# LANGUAGE CPP #-}
{-# LANGUAGE TemplateHaskell #-}
{-# LANGUAGE QuasiQuotes #-}

module System.Hatrace.SyscallTables.Generated where

import           Data.Map (Map)
import qualified Data.Map as Map
import           Language.Haskell.TH
import           Data.Word (Word32, Word64)

import           System.Hatrace.SyscallTables (readSyscallTable)
import           System.Hatrace.SyscallTables.Util (mkSyscallName)


$(do
  -- We use the x86_64 table to extract the names for the data type.
  table <- runIO $ readSyscallTable "syscalls-table/tables/syscalls-x86_64"

  -- Generates `data KnownSyscall = Syscall_Read | Syscall_Write | ...`
  let constructors =
        [ NormalC (mkSyscallName name) [] | (name, _num) <- table ]
  let data_Syscalls =
        DataD
          []
          (mkName "KnownSyscall")
          []
          Nothing
          constructors
#if MIN_VERSION_template_haskell(2,12,0)
          [DerivClause Nothing [ConT ''Eq, ConT ''Ord, ConT ''Show]]
#else
                               [ConT ''Eq, ConT ''Ord, ConT ''Show]
#endif

  return
    [ data_Syscalls
    ]

 )


syscallName :: KnownSyscall -> String
syscallName =
  $(do
    -- We use the x86_64 table to extract the names for the rendering function.
    table <- runIO $ readSyscallTable "syscalls-table/tables/syscalls-x86_64"

    return $ LamCaseE [ Match (ConP (mkSyscallName name) []) (NormalB $ LitE $ StringL name) [] | (name, _) <- table ]
  )


syscallMap_x64_64 :: Map Word64 KnownSyscall
syscallMap_x64_64 =
  $(do
    table <- runIO $ readSyscallTable "syscalls-table/tables/syscalls-x86_64"

    [| Map.fromList $(return $ ListE [ TupE [LitE (IntegerL (fromIntegral num)), ConE (mkName ("Syscall_" ++ name))] | (name, Just num) <- table ]) |]
  )


syscallMap_i386 :: Map Word32 KnownSyscall
syscallMap_i386 =
  $(do
    table <- runIO $ readSyscallTable "syscalls-table/tables/syscalls-i386"

    [| Map.fromList $(return $ ListE [ TupE [LitE (IntegerL (fromIntegral num)), ConE (mkName ("Syscall_" ++ name))] | (name, Just num) <- table ]) |]
  )
