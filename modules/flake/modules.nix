{ inputs, ... }:

{
  flake.nixosModules.default = import ../nixos/ranet-lite.nix { inherit (inputs) self; };
  flake.darwinModules.default = import ../darwin/ranet-lite.nix { inherit (inputs) self; };
}
