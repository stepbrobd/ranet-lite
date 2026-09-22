{
  lib,
  buildGoApplication,
  # the commit this build came from, which tells two nodes apart between
  # releases: version.txt moves once per release and a fleet converts one node
  # at a time in between
  revision ? null,
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
          # code. This is an allow list, so a package promoted out of internal
          # has to be named here in the same commit that moves it, or the
          # sandbox builds a tree that cannot compile.
          ./cmd
          ./control
          ./esp
          ./internal
          ./sadr
          ./transport
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
    ]
    ++ lib.optional (
      revision != null
    ) "-X github.com/NickCao/ranet-lite/internal/version.Revision=${revision}";

    # the test suite runs as a flake check, never inside the package build
    doCheck = false;
  })
)
