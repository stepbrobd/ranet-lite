{
  inputs,
  lib,
  buildGoApplication,
}:

let
  root = ../..;

  # the commit this build came from, which tells two nodes apart between
  # releases: version.txt moves once per release and a fleet converts one node
  # at a time in between. A dirty tree has no revision to report.
  revision = inputs.self.shortRev or inputs.self.dirtyShortRev or null;
in
buildGoApplication (
  lib.fix (finalAttrs: {
    meta.mainProgram = finalAttrs.pname;
    pname = "ranet-lite";
    version = lib.fileContents (root + "/version.txt");

    src =
      with lib.fileset;
      toSource {
        inherit root;
        fileset = unions [
          # code. This is an allow list, so a package promoted out of internal
          # has to be named here in the same commit that moves it, or the
          # sandbox builds a tree that cannot compile.
          (root + "/cmd")
          (root + "/control")
          (root + "/esp")
          (root + "/internal")
          (root + "/sadr")
          (root + "/schema")
          (root + "/srv6")
          (root + "/transport")
          # the example is parsed by a test, so it has to be in the source the
          # checks see or that test passes only outside the sandbox
          (root + "/examples")
          # and the readme is read by the prose checks, for the same reason:
          # without it here they walk the go files alone and say nothing
          (root + "/readme.md")
          # the prose rules cover the nix and python that build and measure
          # this too, and those checks count what they reached, so a source
          # missing them fails rather than narrowing in silence
          (root + "/integration")
          (root + "/lib")
          (root + "/modules")
          (root + "/pkgs")
          (root + "/flake.nix")
          # meta
          (root + "/go.mod")
          (root + "/go.sum")
          (root + "/gomod2nix.toml")
          (root + "/version.txt")
        ];
      };

    modules = root + "/gomod2nix.toml";

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
