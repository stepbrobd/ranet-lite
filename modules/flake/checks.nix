{ inputs, lib, ... }:

{
  perSystem =
    {
      config,
      nixosTest,
      pkgs,
      system,
      ...
    }:
    let
      # nixos vm tests need a linux builder with kvm
      linux = lib.hasSuffix "linux" system;

      # a go tool run inside the package build, so the modules are on hand
      go =
        name: tools: command:
        config.packages.default.overrideAttrs (old: {
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

      # the internal/kernel and internal/egress test binaries, to be run as
      # root in a vm where the netlink round trips they hold are not skipped
      netlinkTests = config.packages.default.overrideAttrs (_: {
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

      # the nixos module evaluated into the unit it generates. A machine that
      # imports it is the only other way to learn that an option name or a
      # type is wrong, since the vm arms configure the daemon by hand rather
      # than through the module.
      node = inputs.nixpkgs.lib.nixosSystem {
        modules = [
          inputs.self.nixosModules.default
          {
            nixpkgs.hostPlatform = system;
            system.stateVersion = lib.trivial.release;
            services.ranet-lite = {
              enable = true;
              settings.node = {
                org = "example";
                name = "check";
              };
            };
          }
        ];
      };
    in
    {
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
              cd ${../../.}
              export DENO_DIR="$TMPDIR/deno"
              deno fmt --check readme.md
              # found rather than globbed, so a directory added under modules,
              # lib or pkgs cannot quietly drop out of the check. The count
              # tells a narrowed walk from a tree that lost files, the same
              # guard the prose checks in internal use.
              files="$(find . -name '*.nix' -not -path './.claude/*' | sort)"
              reached="$(printf '%s\n' "$files" | wc -l)"
              if [ "$reached" -lt 15 ]; then
                echo "the format check reached $reached nix files, want at least 15" >&2
                exit 1
              fi
              nixfmt --check $files
              taplo format --check atelier.toml examples/*.toml gomod2nix.toml
              touch "$out"
            '';
      }
      // lib.optionalAttrs linux {
        integration = nixosTest { };
        integration-multicore = nixosTest { cores = 4; };
        responder = nixosTest { responder = true; };
        kernel = nixosTest { kernel = true; };
        segments = nixosTest { segments = true; };
        egress = nixosTest { egress = true; };
        netlink = pkgs.testers.runNixOSTest (
          import ../../integration/netlink-test.nix { inherit pkgs netlinkTests; }
        );
        nixos-module = pkgs.runCommand "ranet-lite-nixos-module" { } ''
          unit="${node.config.systemd.units."ranet-lite.service".unit}/ranet-lite.service"
          grep -qF 'ExecStart=${lib.getExe config.packages.default} daemon --config ' "$unit"
          # the runtime directory is where the control socket is bound and the
          # group is who may then read it, so a typo in either leaves a node
          # nobody can ask anything or one anybody can
          grep -qF 'RuntimeDirectory=ranet-lite' "$unit"
          grep -qF 'Group=ranet-lite' "$unit"
          touch "$out"
        '';
      };
    };
}
