# The netlink round trips in internal/kernel need root and a network namespace
# to make a mess in, so they skip themselves under the go check, which builds
# as an unprivileged user. That left every rule and VRF write, and the
# FRA_PROTOCOL ownership they rest on, asserted nowhere any check ran. This is
# the same test binary, run as root against a real kernel.
{
  pkgs,
  netlinkTests,
}:
{
  name = "ranet-lite-netlink";

  # The tests build their own namespaces, links and rules, so the machine needs
  # nothing but a kernel, root and iproute2 to read the result back with.
  nodes.machine.environment.systemPackages = [ pkgs.iproute2 ];

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # -test.v so a failure names the round trip rather than the package, and
    # the count so a pass here means the binary ran them rather than skipping
    # them for the same reason the go check does.
    out = machine.succeed(
        "${netlinkTests}/bin/netlink-tests -test.v -test.run 'TestNetlink' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the tests skipped themselves under root:\n{out}"
    ran = out.count("--- PASS")
    assert ran >= 4, f"only {ran} netlink round trips ran:\n{out}"

    # Nothing the tests wrote may outlive them: they run against the host's own
    # kernel here rather than against a fake, so a rule or a VRF left behind is
    # a leak this check is the only thing positioned to see.
    assert "proto 155" not in machine.succeed("ip rule show; ip -6 rule show")
    machine.fail("ip link show gravity")
  '';
}
