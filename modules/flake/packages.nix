{ lib, ... }:

{
  perSystem =
    {
      config,
      nixosTest,
      pkgs,
      system,
      ...
    }:
    {
      packages = {
        default = pkgs.ranet-lite;
        iperf3-benchmark = pkgs.iperf3-benchmark;
      }
      # profiling variants are built on demand, never as part of a check
      // lib.optionalAttrs (lib.hasSuffix "linux" system) {
        integration-profile = nixosTest {
          cores = 4;
          profile = true;
        };
        namespace-profile = pkgs.testers.runNixOSTest (
          import ../../integration/nixos-performance.nix {
            inherit pkgs;
            ranetLite = config.packages.default;
            benchmarkIperf = config.packages.iperf3-benchmark;
          }
        );
      };
    };
}
