{
  lib,
  mkShell,
  bird3,
  deno,
  ethtool,
  go,
  go-tools,
  gomod2nix,
  gopls,
  iperf3,
  iproute2,
  iputils,
  pprof,
  python3,
  stdenv,
  strongswan,
  util-linux,
}:

mkShell {
  packages = [
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
    iperf3
    iproute2
    iputils
    strongswan
    util-linux
  ];
}
