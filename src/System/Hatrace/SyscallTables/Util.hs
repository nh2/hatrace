module System.Hatrace.SyscallTables.Util where

import           Language.Haskell.TH


mkSyscallName :: String -> Name
mkSyscallName name = mkName ("Syscall_" ++ name)
