# Adapted from stepbrobd/inc, MIT. The scope recursion is kept as it is there
# so that a package directory added here behaves the same way it would in inc
# or in howfastly, even though this tree has only flat ones today.
{ lib }:

# importPackagesTree { dir, currentFinal, currentPrev, inheritedArgs }
{
  dir,
  currentFinal,
  currentPrev,
  inheritedArgs ? { },
}:

let
  inherit (lib)
    callPackageWith
    childDirsWithDefault
    importPackagesTree
    isAttrs
    isDerivation
    isFunction
    length
    makeScope
    mkDynamicAttrs
    pathExists
    tryEval
    ;

  # a top level package argument (fetchgit) stays reachable where a scope
  # argument (mkDerivation) shadows it, and an inherited argument wins over
  # both, so lib, inputs, pkgsFinal and pkgsPrev always mean the flake's
  callArgs = (inheritedArgs.pkgsFinal or currentFinal) // currentFinal // inheritedArgs;
in
mkDynamicAttrs {
  inherit dir;
  fun =
    name:
    let
      pkg = dir + "/${name}";
      hasDefaultNix = pathExists (pkg + "/default.nix");
      childScopeNames = if !hasDefaultNix then childDirsWithDefault pkg else [ ];
      hasChildScopes = length childScopeNames > 0;

      # currentPrev is touched only where the local path has no default.nix,
      # and an alias that throws is caught rather than failing the overlay
      hasScopeAttr = !hasDefaultNix && currentPrev ? ${name};
      scopeEval =
        if hasScopeAttr then
          tryEval currentPrev.${name}
        else
          {
            success = false;
            value = null;
          };
      hasScopeValue = scopeEval.success;
      scopeValue = if hasScopeValue then scopeEval.value else null;
      hasOverrideScope = hasScopeValue && isAttrs scopeValue && scopeValue ? overrideScope;
      hasExtend = hasScopeValue && isAttrs scopeValue && scopeValue ? extend;

      # duck-typed: some scopes expose extend rather than overrideScope, as
      # haskellPackages does. Do not name a directory here after an extensible
      # attribute that is not a package scope, since pkgs/lib would extend lib.
      isScope =
        hasScopeValue && isAttrs scopeValue && !isDerivation scopeValue && (hasOverrideScope || hasExtend);
      scopeOverride = if hasOverrideScope then scopeValue.overrideScope else scopeValue.extend;
    in
    if hasDefaultNix then
      let
        imported = import pkg;
      in
      # a local default.nix wins over whatever currentPrev calls the same thing
      if !isFunction imported then imported else callPackageWith callArgs pkg { }
    # an existing scope in currentPrev, extended rather than replaced
    else if isScope then
      scopeOverride (
        scopeFinal: scopePrev:
        importPackagesTree {
          dir = pkg;
          currentFinal = scopeFinal;
          currentPrev = scopePrev;
          inheritedArgs = inheritedArgs // {
            "${name}Final" = scopeFinal;
            "${name}Prev" = scopePrev;
          };
        }
      )
    # a scope of this tree's own, named by a directory of packages
    else if hasChildScopes then
      makeScope callPackageWith (
        localScopeFinal:
        importPackagesTree {
          dir = pkg;
          currentFinal = localScopeFinal;
          # a fresh scope has nothing to override, and letting the outer prev
          # in would misroute a child whose name matches a root attribute
          currentPrev = { };
          inheritedArgs = inheritedArgs // {
            "${name}Final" = localScopeFinal;
            "${name}Prev" = localScopeFinal;
          };
        }
      )
    else
      throw "path ${toString pkg} has no default.nix and is not a scope";
}
