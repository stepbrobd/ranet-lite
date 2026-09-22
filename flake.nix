{
  description = "A lightweight ranet client";

  outputs =
    { self, ... }@inputs:
    inputs.autopilot.lib.mkFlake {
      inherit inputs;

      autopilot = {
        lib.path = ./lib;
        lib.extender = inputs.nixpkgs.lib;
        lib.extensions = with inputs; [
          autopilot.lib
          parts.lib
        ];

        nixpkgs.instances.pkgs = inputs.nixpkgs;
        nixpkgs.overlays = with inputs; [
          # buildGoApplication, which pkgs/ranet-lite is written against
          gomod2nix.overlays.default
          self.overlays.default
        ];

        parts.path = ./modules/flake;
      };
    } { systems = import inputs.systems; };

  inputs = {
    nixpkgs.url = "github:nixos/nixpkgs/nixos-unstable-small";
    systems.url = "github:nix-systems/triplet";
    parts.url = "github:hercules-ci/flake-parts";
    parts.inputs.nixpkgs-lib.follows = "nixpkgs";
    autopilot.url = "github:stepbrobd/autopilot";
    autopilot.inputs.nixpkgs.follows = "nixpkgs";
    autopilot.inputs.parts.follows = "parts";
    autopilot.inputs.systems.follows = "systems";
    utils.url = "github:numtide/flake-utils";
    utils.inputs.systems.follows = "systems";
    gomod2nix.url = "github:nix-community/gomod2nix";
    gomod2nix.inputs.nixpkgs.follows = "nixpkgs";
    gomod2nix.inputs.flake-utils.follows = "utils";
  };

  nixConfig = {
    extra-substituters = [ "https://cache.ysun.co" ];
    extra-trusted-public-keys = [ "cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=" ];
  };
}
