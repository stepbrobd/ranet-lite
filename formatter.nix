{
  lib,
  writeShellScriptBin,
  deno,
  go,
  go-tools,
  gomod2nix,
  nixfmt-tree,
  taplo,
}:

writeShellScriptBin "formatter" ''
  set -eoux pipefail
  shopt -s globstar

  root="$PWD"
  while [[ ! -f "$root/.git/index" ]]; do
    if [[ "$root" == "/" ]]; then
      exit 1
    fi
    root="$(dirname "$root")"
  done
  pushd "$root" > /dev/null

  ${lib.getExe deno} fmt **/*.md
  ${lib.getExe nixfmt-tree} .
  ${lib.getExe taplo} format **/*.toml

  ${lib.getExe go} fmt ./...
  ${lib.getExe go} vet ./...
  ${lib.getExe' go-tools "staticcheck"} ./...
  ${lib.getExe' gomod2nix "gomod2nix"}

  popd
''
