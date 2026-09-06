{
  description = "A lightweight ranet client";

  inputs.nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";

  outputs =
    { nixpkgs, ... }:
    let
      system = "x86_64-linux";
      pkgs = import nixpkgs { inherit system; };
      ranet-lite = pkgs.buildGoModule {
        pname = "ranet-lite";
        version = "0.1.0";
        src = ./.;
        vendorHash = "sha256-3FRdONnzY53jXsC7j6Ig6BwjCF09Qn2PZxnqXzAYoBY=";
        subPackages = [ "cmd/ranet-lite" ];
      };
      integration =
        args:
        pkgs.testers.runNixOSTest (
          import ./integration/nixos-test.nix (
            {
              inherit pkgs;
              ranetLite = ranet-lite;
            }
            // args
          )
        );
    in
    {
      packages.${system} = {
        inherit ranet-lite;
        default = ranet-lite;
        integration-profile = integration {
          cores = 4;
          profile = true;
        };
        namespace-profile = pkgs.testers.runNixOSTest (
          import ./integration/nixos-performance.nix {
            inherit pkgs;
            ranetLite = ranet-lite;
          }
        );
      };

      devShells.${system}.default = pkgs.mkShell {
        packages = with pkgs; [
          go
          python3
          iproute2
          util-linux
          iputils
          strongswan
          bird3
          iperf3
          ethtool
          pprof
        ];
      };

      checks.${system} = {
        integration = integration { };
        integration-multicore = integration { cores = 4; };
      };
    };
}
