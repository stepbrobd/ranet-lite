{
  perSystem =
    { lib, pkgs, ... }:
    {
      formatter = pkgs.writeShellScriptBin "formatter" ''
        set -eoux pipefail
        shopt -s globstar

        # in a linked worktree .git is a file, so walking up for .git/index escapes
        # the worktree and formats whatever checkout is above it
        root="$(${lib.getExe pkgs.git} rev-parse --show-toplevel)"
        pushd "$root" > /dev/null

        ${lib.getExe pkgs.deno} fmt **/*.md
        ${lib.getExe pkgs.nixfmt-tree} .

        ${lib.getExe pkgs.go} fmt ./...
        ${lib.getExe pkgs.go} vet ./...
        ${lib.getExe' pkgs.go-tools "staticcheck"} ./...
        # before taplo, because gomod2nix rewrites gomod2nix.toml in its own layout
        # and formatting it first would leave the tree unformatted again
        ${lib.getExe' pkgs.gomod2nix "gomod2nix"}
        ${lib.getExe pkgs.go} run ./internal/cmd/notices
        ${lib.getExe pkgs.taplo} format **/*.toml

        popd
      '';
    };
}
