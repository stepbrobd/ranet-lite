{
  perSystem =
    {
      config,
      lib,
      pkgs,
      ...
    }:
    {
      devShells.default = pkgs.mkShell {
        packages =
          with pkgs;
          [
            deno
            go
            go-tools
            gomod2nix
            gopls
            pprof
            python3
          ]
          # the integration harness and the namespace benchmark are linux only
          ++ lib.optionals stdenv.hostPlatform.isLinux [
            bird3
            ethtool
            config.packages.iperf3-benchmark
            iproute2
            iputils
            strongswan
            util-linux
          ];
      };
    };
}
