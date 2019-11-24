with (import <nixpkgs> {});
let
  # Needs NUR from https://github.com/nix-community/NUR
  ghc = nur.repos.mpickering.ghc.ghc863; # Keep in sync with the GHC version defined by stack.yaml!
in
  haskell.lib.buildStackProject {
    inherit ghc;
    name = "myEnv";
    nativeBuildInputs = [ git ];
    # We need both glibc and glibc.static because GHC needs the former,
    # but for building our test executables with `gcc -static` we need the latter.
    buildInputs = [ glibc glibc.static nasm gnumake ];
  }
