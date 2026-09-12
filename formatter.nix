{
  lib,
  writeShellScriptBin,
  deno,
  git,
  go,
  go-tools,
  gomod2nix,
  nixfmt-tree,
  taplo,
}:

writeShellScriptBin "formatter" ''
  set -eoux pipefail
  shopt -s globstar

  # in a linked worktree .git is a file, so walking up for .git/index escapes
  # the worktree and formats whatever checkout is above it
  root="$(${lib.getExe git} rev-parse --show-toplevel)"
  pushd "$root" > /dev/null

  ${lib.getExe deno} fmt **/*.md
  ${lib.getExe nixfmt-tree} .

  ${lib.getExe go} fmt ./...
  ${lib.getExe go} vet ./...
  ${lib.getExe' go-tools "staticcheck"} ./...
  # before taplo, because gomod2nix rewrites gomod2nix.toml in its own layout
  # and formatting it first would leave the tree unformatted again
  ${lib.getExe' gomod2nix "gomod2nix"}
  ${lib.getExe taplo} format **/*.toml

  popd
''
