# Adapted from stepbrobd/inc, MIT.
{ lib }:

# childDirsWithDefault :: Path -> [String]
dir:

let
  inherit (lib)
    attrNames
    filter
    pathExists
    readDir
    ;

  entries = readDir dir;
in
filter (name: entries.${name} == "directory" && pathExists (dir + "/${name}/default.nix")) (
  attrNames entries
)
