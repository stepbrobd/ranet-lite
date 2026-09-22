{
  pkgs,
  ranetLite,
  benchmarkIperf ? pkgs.callPackage ../pkgs/iperf3-benchmark { },
}:

{
  name = "ranet-lite-namespace-profile";

  nodes.machine = {
    virtualisation.cores = 6;
    virtualisation.memorySize = 4096;
    boot.kernelModules = [
      "tun"
      "xfrm_interface"
    ];
    users.users.bench.isNormalUser = true;
    environment.systemPackages = with pkgs; [
      python3
      iproute2
      util-linux
      iputils
      strongswan
      bird3
      benchmarkIperf
      ethtool
      perf
    ];
  };

  testScript = ''
    import datetime as dt

    start_all()
    machine.wait_for_unit("multi-user.target")
    # Keep the same private veth topology as the host benchmark. Profiling
    # inside this VM provides kernel symbols without host root permissions
    # or the userspace virtual switch used between integration-test VMs.
    machine.succeed("echo kvm-clock > /sys/devices/system/clocksource/clocksource0/current_clocksource")
    machine.succeed("perf record -a -e cpu-clock:k -F 99 -g -o /tmp/kernel.perf -- sleep 180 > /tmp/perf.log 2>&1 & echo $! > /tmp/perf.pid")
    try:
        print(machine.succeed("runuser -u bench -- unshare --user --map-root-user --mount --net python3 ${./performance.py} --repo ${../.} --client ${ranetLite}/bin/ranet-lite --output /tmp/ranet-performance --cores 6 --duration 15 --directions outbound,inbound,bidir", timeout=dt.timedelta(seconds=150)))
    finally:
        machine.execute("kill -INT $(cat /tmp/perf.pid)")
        machine.wait_until_fails("kill -0 $(cat /tmp/perf.pid)")
        print(machine.succeed("cat /tmp/perf.log"))
        print(machine.succeed("perf report --stdio --no-children --percentage relative --percent-limit 1 -g none --comms ranet-lite -i /tmp/kernel.perf"))
        # Preserve the guest's symbol addresses for analysis on another kernel.
        machine.succeed("cat /proc/kallsyms > /tmp/kernel.kallsyms")
        machine.copy_from_machine("/tmp/kernel.kallsyms")
        machine.copy_from_machine("/tmp/kernel.perf")
        machine.copy_from_machine("/tmp/ranet-performance")
  '';
}
