# The netlink round trips in internal/kernel and internal/egress need root and
# a network namespace to make a mess in, so they skip themselves under the go
# check, which builds as an unprivileged user. That left every rule and VRF
# write, the FRA_PROTOCOL ownership they rest on, and every byte of the
# nf_tables encoding asserted nowhere any check ran. These are the same test
# binaries, run as root against a real kernel.
{
  pkgs,
  netlinkTests,
}:
{
  name = "ranet-lite-netlink";

  # The tests build their own namespaces, links, rules and tables, so the
  # machine needs nothing but a kernel, root, and iproute2 and nft to read the
  # result back with.
  nodes.machine.environment.systemPackages = [
    pkgs.iproute2
    pkgs.nftables
  ];

  testScript = ''
    machine.wait_for_unit("multi-user.target")

    # The host's own nftables tables, whatever they are. This machine runs the
    # NixOS firewall through iptables-nft, so four of them are here before
    # anything under test has run, and the assertion below has to be about this
    # tool's own name rather than about the ruleset being empty.
    def foreign():
        return [t for t in machine.succeed("nft list tables").splitlines() if "ranet-lite" not in t]

    before = foreign()
    print("the host's own tables:", before)

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

    # The nf_tables half. A fake backend can only ever agree with the encoder
    # it was written beside, so what the kernel accepts, and the spelling it
    # hands back for a diff to compare against, is checked here and nowhere
    # else short of the full exit node arm.
    out = machine.succeed(
        "${netlinkTests}/bin/egress-tests -test.v -test.run 'TestNftablesRoundTrip' 2>&1"
    )
    print(out)
    assert "SKIP" not in out, f"the nftables round trip skipped itself under root:\n{out}"
    assert "--- PASS" in out, f"the nftables round trip did not run:\n{out}"

    # Nothing the tests wrote may outlive them: they run against the host's own
    # kernel here rather than against a fake, so a rule, a VRF or a table left
    # behind is a leak this check is the only thing positioned to see.
    assert "proto 155" not in machine.succeed("ip rule show; ip -6 rule show")
    machine.fail("ip link show mesh")
    tables = machine.succeed("nft list tables")
    assert "ranet-lite" not in tables, f"a table outlived the namespace it was written in:\n{tables}"
    # And nothing of the host's went with it: the tests write into a namespace
    # of their own, so the four tables the firewall had are still here.
    assert foreign() == before, f"the host's own tables changed under the tests: {before} then {foreign()}"
  '';
}
