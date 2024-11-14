{
  description = "C++ Development with Nix in 2023";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs = inputs@{ flake-parts, ... }:
    flake-parts.lib.mkFlake { inherit inputs; } {
      systems = [
        "x86_64-linux" 
      ];
      perSystem = { config, self', inputs', pkgs, system, ... }: {
        devShells.default = pkgs.mkShell {
            shellHook = ''
              ${pkgs.bash}/bin/bash
          '';
          packages = with pkgs; [
            boost
            meson
            ninja
            gcc
            libglibutil
            pkg-config
            catch2
            cmake
            go-task
            eigen
            opencv
            clang-tools
            glib
            glibc
            gusb
            gobject-introspection
            pixman
            cairo
            cairomm
            cairosvg
            nss
            libgudev
            gtk-doc
            gdb
            valgrind

            # Add libfprint with an override
            (pkgs.libfprint.overrideAttrs (oldAttrs: {
              src = pkgs.fetchFromGitHub {
              owner = "Xelef2000";
              repo = "libfprint";
              rev = "56dc7f7524dabc0da55f2a15f7706e73778aa5e7";
              hash = "sha256-ySifkClM6qjDlm8iPMwWngHs5PrB1reddreziIUEs5k=";
            };
            }))
          ];
        };
      };
    };
}
