# Adapted from stepbrobd/inc, MIT, which carries the original of this file and
# of the two beside it.
{ lib }:

# mkDynamicAttrs { dir, fun }
{ dir, fun }:

let
  inherit (lib)
    attrNames
    filter
    genAttrs
    readDir
    ;

  entries = readDir dir;

  # stray files (readme.md, .DS_Store) are not packages
  dirs = filter (name: entries.${name} == "directory") (attrNames entries);
in
genAttrs dirs fun
