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
            umockdev
            python312Packages.pygobject3
            python312Packages.pygobject-stubs
            tshark
            # (pkgs.callPackage ./cros-ectool.nix { })

            # Add libfprint with an override
            (pkgs.libfprint.overrideAttrs (oldAttrs: {
              src = pkgs.fetchFromGitHub {
              owner = "Xelef2000";
              repo = "libfprint";
              rev = "05bd17f8eb3cd25e367c67f153d93d3a3bc61c52";
              hash = "sha256-ySifkClM6qjDlm8iPMwWngHs5PrB1reddreziIUEs5k=";
            };
            }))
          ];
        };
      };
    };
}
