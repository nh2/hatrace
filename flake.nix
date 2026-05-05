{
  description = "scriptable strace";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = { self, nixpkgs }:
    let
      system = "x86_64-linux";
      pkgs = nixpkgs.legacyPackages.${system};

      syscallsTable = pkgs.fetchFromGitHub {
        owner = "hrw";
        repo = "syscalls-table";
        rev = "a0b0ccecef5213f8d93df3edc575e2f39065907b";
        sha256 = "sha256-qMdpegeKPQ1tIvsL3vmnxiow6z8fxhFyE2O+OyfHScc=";
      };

      hatraceSource = pkgs.runCommand "hatrace-source" { } ''
        cp -r ${self} $out
        chmod -R u+w $out
        cp -r ${syscallsTable} $out/syscalls-table
      '';

      haskellPackages = pkgs.haskellPackages.override {
        overrides = hself: hsuper: {
          posix-waitpid = hself.callCabal2nix "posix-waitpid"
            (pkgs.fetchFromGitHub {
              owner = "nh2";
              repo = "posix-waitpid";
              rev = "d2d7e06d85965dd022705d3d4e8348940afabb5f";
              sha256 = "sha256-9YtCAyDymy6U7DwFjdj3y+VGP0+7tn3eyq4RCNpPjvw=";
            }) { };
          linux-ptrace = hself.callCabal2nix "linux-ptrace"
            (pkgs.fetchFromGitHub {
              owner = "nh2";
              repo = "linux-ptrace";
              rev = "8969355c2e1ce095ef58acc5f2c5f8a4ea3f1645";
              sha256 = "sha256-y2fXRBSXa4dlIEegCBA5MyFOb9jW8fdhayBqOifZWk0=";
            }) { };
          hatrace =
            pkgs.haskell.lib.dontHaddock (
            pkgs.haskell.lib.overrideCabal
              (hself.callCabal2nix "hatrace" hatraceSource {
                inherit (hself) linux-ptrace posix-waitpid;
              })
              (drv: {
                configureFlags = (drv.configureFlags or [ ]) ++ [
                  "--ghc-option=-Wno-incomplete-uni-patterns"
                ];
                testToolDepends = (drv.testToolDepends or [ ]) ++ [
                  pkgs.nasm
                  pkgs.gnumake
                ];
                preConfigure = ''
                  sed -i 's/nasm -Wall -Werror/nasm -Wall/g' Makefile
                  sed -i 's/gcc -static -std=c99 -Wall -Werror/gcc -static -std=c99 -Wall -U_FORTIFY_SOURCE/g' Makefile
                  sed -i 's/gcc -static -std=gnu99 -Wall -Werror/gcc -static -std=gnu99 -Wall -U_FORTIFY_SOURCE/g' Makefile
                '';
                preCheck = ''
                  export LIBRARY_PATH="${pkgs.glibc.static}/lib:$LIBRARY_PATH"
                '';
              }));
        };
      };

      hatrace = pkgs.haskell.lib.justStaticExecutables haskellPackages.hatrace;
    in
    {
      packages.${system} = {
        default = hatrace;
        inherit hatrace;
      };

      checks.${system} = {
        build = haskellPackages.hatrace;
      };

      devShells.${system}.default = haskellPackages.shellFor {
        packages = p: [ p.hatrace ];
        buildInputs = [
          pkgs.cabal-install
          pkgs.haskell-language-server
          pkgs.ghcid
          pkgs.nasm
          pkgs.gnumake
        ];
      };
    };
}
