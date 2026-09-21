{
  description = "A lightweight ranet client";

  outputs =
    inputs:
    inputs.parts.lib.mkFlake { inherit inputs; } (
      { lib, ... }:
      {
        systems = import inputs.systems;

        perSystem =
          {
            pkgs,
            system,
            self',
            ...
          }:
          let
            # nixos vm tests need a linux builder with kvm
            linux = lib.hasSuffix "linux" system;

            # a nixos vm test, given the arguments the harness is parameterized on
            integration =
              args:
              pkgs.testers.runNixOSTest (
                import ./integration/nixos-test.nix (
                  {
                    inherit pkgs;
                    ranetLite = self'.packages.default;
                  }
                  // args
                )
              );

            # a go tool run inside the package build, so the modules are on hand
            go =
              name: tools: command:
              self'.packages.default.overrideAttrs (old: {
                pname = "ranet-lite-${name}";
                nativeBuildInputs = old.nativeBuildInputs ++ tools;
                buildPhase = ''
                  export HOME="$TMPDIR"
                  ${command}
                '';
                installPhase = ''touch "$out"'';
                # the ike and transport tests bind loopback, which the darwin
                # sandbox forbids by default
                __darwinAllowLocalNetworking = true;
              });
            # the internal/kernel and internal/egress test binaries, to be run
            # as root in a vm where the netlink round trips they hold are not
            # skipped
            netlinkTests = self'.packages.default.overrideAttrs (old: {
              pname = "ranet-lite-netlink-tests";
              buildPhase = ''
                export HOME="$TMPDIR"
                go test -c -o netlink-tests ./internal/kernel/
                go test -c -o egress-tests ./internal/egress/
              '';
              installPhase = ''
                install -Dm755 netlink-tests "$out/bin/netlink-tests"
                install -Dm755 egress-tests "$out/bin/egress-tests"
              '';
            });
          in
          {
            _module.args.pkgs = import inputs.nixpkgs {
              inherit system;
              overlays = [ inputs.gomod2nix.overlays.default ];
            };

            packages = {
              default = pkgs.callPackage ./default.nix {
                revision = inputs.self.shortRev or inputs.self.dirtyShortRev or null;
              };
              iperf3-benchmark = pkgs.callPackage ./integration/iperf3.nix { };
            }
            # profiling variants are built on demand, never as part of a check
            // lib.optionalAttrs linux {
              integration-profile = integration {
                cores = 4;
                profile = true;
              };
              namespace-profile = pkgs.testers.runNixOSTest (
                import ./integration/nixos-performance.nix {
                  inherit pkgs;
                  ranetLite = self'.packages.default;
                  benchmarkIperf = self'.packages.iperf3-benchmark;
                }
              );
            };

            devShells.default = pkgs.callPackage ./shell.nix {
              iperf3 = self'.packages.iperf3-benchmark;
            };

            formatter = pkgs.callPackage ./formatter.nix { };

            checks = {
              gofmt = go "gofmt" [ ] ''test -z "$(gofmt -l $(go list -f '{{.Dir}}' ./...))"'';
              staticcheck = go "staticcheck" [ pkgs.go-tools ] "staticcheck ./...";
              test = go "test" [ ] "go test -race ./...";
              vet = go "vet" [ ] "go vet ./...";
              # platform_unsupported.go and tun_name_other.go sit behind build
              # tags no configured system matches
              cross = go "cross" [ ] "GOOS=freebsd GOARCH=amd64 CGO_ENABLED=0 go build ./...";
              # the formatter rewrites markdown, nix and toml, so without these
              # only its go half is ever checked
              format =
                pkgs.runCommand "ranet-lite-format"
                  {
                    nativeBuildInputs = [
                      pkgs.deno
                      pkgs.nixfmt
                      pkgs.taplo
                    ];
                  }
                  ''
                    cd ${./.}
                    export DENO_DIR="$TMPDIR/deno"
                    deno fmt --check readme.md
                    nixfmt --check *.nix integration/*.nix
                    taplo format --check atelier.toml examples/*.toml gomod2nix.toml
                    touch "$out"
                  '';
            }
            // lib.optionalAttrs linux {
              integration = integration { };
              integration-multicore = integration { cores = 4; };
              responder = integration { responder = true; };
              kernel = integration { kernel = true; };
              segments = integration { segments = true; };
              egress = integration { egress = true; };
              netlink = pkgs.testers.runNixOSTest (
                import ./integration/netlink-test.nix { inherit pkgs netlinkTests; }
              );
            };
          };
      }
    );

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable-small";
    systems.url = "github:nix-systems/triplet";
    parts.url = "github:hercules-ci/flake-parts";
    parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    utils.url = "github:numtide/flake-utils";
    utils.inputs.systems.follows = "systems";
    gomod2nix.url = "github:nix-community/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
    gomod2nix.inputs.flake-utils.follows = "utils";
  };

  nixConfig = {
    extra-substituters = [ "https://cache.ysun.co" ];
    extra-trusted-public-keys = [ "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=" ];
  };
}
