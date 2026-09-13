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
    ];

    # the test suite runs as a flake check, never inside the package build
    doCheck = false;
  })
)
