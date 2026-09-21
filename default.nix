{
  lib,
  buildGoApplication,
}:

buildGoApplication (
  lib.fix (finalAttrs: {
    meta.mainProgram = finalAttrs.pname;
    pname = "ranet-lite";
    version = lib.fileContents ./version.txt;

    src =
      with lib.fileset;
      toSource {
        root = ./.;
        fileset = unions [
          # code
          ./cmd
          ./esp
          ./internal
          ./sadr
          # the example is parsed by a test, so it has to be in the source the
          # checks see or that test passes only outside the sandbox
          ./examples
          # and the readme is read by the prose checks, for the same reason:
          # without it here they walk the go files alone and say nothing
          ./readme.md
          # the prose rules cover the nix and python that build and measure
          # this too, and those checks count what they reached, so a source
          # missing them fails rather than narrowing in silence
          ./integration
          ./default.nix
          ./flake.nix
          ./formatter.nix
          ./shell.nix
          # meta
          ./go.mod
          ./go.sum
          ./gomod2nix.toml
          ./version.txt
        ];
      };

    modules = ./gomod2nix.toml;

    subPackages = [ "cmd/ranet-lite" ];

    ldflags = [
      "-s"
      "-w"
      "-X github.com/NickCao/ranet-lite/internal/version.Value=${finalAttrs.version}"
    ];

    # the test suite runs as a flake check, never inside the package build
    doCheck = false;
  })
)
