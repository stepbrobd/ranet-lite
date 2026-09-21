{
  pkgs,
  ranetLite,
  cores ? 1,
  profile ? false,
  # responder inverts the exchange: strongSwan dials and ranet-lite answers,
  # which is the direction upstream could not do at all.
  responder ? false,
  # kernel turns on the route reconciler, so the routes babel learns from BIRD
  # have to reach a real kernel table rather than only the in-process trie.
  kernel ? false,
  # segments steers one destination through a segment routing header that the
  # gateway's own kernel decapsulates, so this tree's encapsulation is checked
  # against the implementation it has to interoperate with rather than against
  # its own decoder.
  segments ? false,
}:

let
  gatewayTunnel = "fd00:99::1";
  clientTunnel = "fd00:88::2";
  gatewayTunnelV4 = "10.99.0.1";
  kernelTable = 200;
  kernelProtocol = 155;
  clientTunnelV4 = "10.88.0.2";
  # Inside the /64 BIRD already announces, so the segment is reachable over
  # the mesh without a second announcement to keep in step with this one.
  gatewaySID = "fd00:99::6:1";
  gatewayBehind = "fd00:99::9";
  # The mirror image, for the direction where the gateway's kernel builds the
  # header and this tree acts on it. The SID is announced so the gateway can
  # route to it, and clientBehind is not, so the only way a packet reaches it
  # is the segment.
  clientSID = "fd00:88::6:1";
  # On loopback rather than on the tun: an address on the tun is one the kernel
  # can pick as the source for the mesh traffic that leaves through it, and
  # nothing announces this one, so the replies would have nowhere to go.
  clientBehind = "fd00:88::9";
  publicKey = builtins.readFile ./org-pub.pem;

  common = {
    virtualisation.vlans = [ 1 ];
    virtualisation.cores = cores;
    networking = {
      useNetworkd = true;
      useDHCP = false;
      firewall.enable = false;
    };
  };
in
{
  name =
    if responder then
      "ranet-lite-responder"
    else if kernel then
      "ranet-lite-kernel"
    else if segments then
      "ranet-lite-segments"
    else
      "ranet-lite-integration";

  nodes = {
    gateway =
      { config, nodes, ... }:
      {
        imports = [ common ];

        boot.kernelModules = [ "xfrm_interface" ];

        # The gateway is the peer this tree has to interoperate with, so the
        # segment it answers for is the kernel's own End behavior rather than
        # anything from this repository. default covers swan0, which
        # strongSwan creates once the SA is up and after any boot-time sysctl
        # would have run.
        boot.kernel.sysctl = pkgs.lib.mkIf segments {
          "net.ipv6.conf.all.seg6_enabled" = 1;
          "net.ipv6.conf.default.seg6_enabled" = 1;
          # A node answering for a segment is a router for it, and a kernel
          # with forwarding off drops the packet in ip6_forward and counts
          # Ip6InAddrErrors, which reads as an address problem rather than as
          # a policy one. The fleet's own nodes set this too.
          "net.ipv6.conf.all.forwarding" = 1;
        };

        environment.systemPackages =
          with pkgs;
          [
            bird2
            iperf3
            iproute2
            config.services.strongswan-swanctl.package
          ]
          # A capture is the only thing that tells a packet that never arrived
          # from one the far end refused.
          ++ pkgs.lib.optionals segments [ tcpdump ];

        environment.etc = {
          "swanctl/private/org-key.pem".source = ./org-key.pem;
          "swanctl/pubkey/org-pub.pem".source = ./org-pub.pem;
        };

        systemd.network = {
          netdevs."20-swan0" = {
            netdevConfig = {
              Name = "swan0";
              Kind = "xfrm";
            };
            xfrmConfig.InterfaceId = 1;
          };
          networks = {
            # The test network module already defines 40-eth1; extend it to
            # create swan0 with eth1 as its underlying device.
            "40-eth1".networkConfig.Xfrm = "swan0";
            "40-swan0" = {
              matchConfig.Name = "swan0";
              linkConfig = {
                Multicast = true;
                RequiredForOnline = false;
              };
              networkConfig.ConfigureWithoutCarrier = true;
              addresses = [
                { Address = "fe80::1/64"; }
                { Address = "${gatewayTunnel}/64"; }
                { Address = "${gatewayTunnelV4}/24"; }
              ]
              # The steered destination goes here rather than on lo, because
              # the tunnel prefix is a connected /64 on this link: an address
              # inside it that is not assigned locally is one the gateway
              # sends straight back to the client.
              ++ pkgs.lib.optionals segments [ { Address = "${gatewayBehind}/128"; } ];
            };
          };
        };

        services.strongswan-swanctl = {
          enable = true;
          strongswan.extraConfig = ''
            charon-systemd {
              interfaces_use = eth1
              port = 0
              port_nat_t = 13000
            }
          '';
          swanctl = {
            connections.ranet = {
              version = 2;
              local_addrs = [ "0.0.0.0/0" ];
              # A wildcard remote can only answer. Naming the client lets
              # swanctl --initiate dial it.
              remote_addrs = if responder then [ nodes.client.networking.primaryIPAddress ] else [ "0.0.0.0/0" ];
              local_port = 13000;
              remote_port = 14000;
              encap = true;
              mobike = false;
              dpd_delay = "10s";
              keyingtries = 0;
              unique = "replace";
              if_id_in = "1";
              if_id_out = "1";
              local.main = {
                auth = "pubkey";
                pubkeys = [ "org-pub.pem" ];
                id = "O=testorg, CN=server, serialNumber=1";
              };
              remote.main = {
                auth = "pubkey";
                pubkeys = [ "org-pub.pem" ];
                id = "O=testorg, CN=client, serialNumber=2";
              };
              children.default = {
                local_ts = [
                  "0.0.0.0/0"
                  "::/0"
                ];
                remote_ts = [
                  "0.0.0.0/0"
                  "::/0"
                ];
                mode = "tunnel";
                dpd_action = "restart";
                start_action = "none";
                close_action = "none";
              };
            };
          };
        };

        systemd.services.strongswan-swanctl = {
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
        };

        services.bird = {
          enable = true;
          package = pkgs.bird3;
          config = ''
            ipv6 sadr table sadr6;

            protocol device {
              scan time 1;
            }

            protocol kernel {
              ipv6 sadr {
                export all;
                import none;
              };
            }

            protocol static {
              ipv6 sadr ;
              route fd00:99::/64 from ::/0 unreachable;
            }

            protocol kernel kernel4 {
              ipv4 {
                export all;
                import none;
              };
            }

            protocol static static4 {
              ipv4;
              route 10.99.0.0/24 unreachable;
            }

            protocol babel {
              ipv4 {
                export all;
                import all;
              };
              ipv6 sadr {
                export all;
                import all;
              };
              randomize router id;
              interface "swan0" {
                type tunnel;
                rxcost 96;
                hello interval 500 ms;
                update interval 1 s;
                rtt cost 1024;
                rtt max 1024 ms;
                rx buffer 1500;
              };
            }
          '';
        };

        systemd.services.bird = {
          requires = [ "network-online.target" ];
          after = [ "network-online.target" ];
        };

        services.iperf3 = {
          enable = true;
          bind = gatewayTunnel;
        };
      };

    client =
      { nodes, ... }:
      {
        imports = [ common ];

        boot.kernelModules = [ "tun" ];
        environment.systemPackages =
          with pkgs;
          [
            curl
            iperf3
            iproute2
            ranetLite
          ]
          ++ lib.optionals profile [
            pprof
            perf
          ];

        systemd.network = {
          netdevs."20-ranet0" = {
            netdevConfig = {
              Name = "ranet0";
              Kind = "tun";
            };
            tunConfig = {
              MultiQueue = true;
              PacketInfo = false;
              VNetHeader = true;
            };
          };
          networks."05-lo" = pkgs.lib.mkIf segments {
            matchConfig.Name = "lo";
            networkConfig.ConfigureWithoutCarrier = true;
            # What an End.DT46 on this node delivers to, reachable through the
            # segment and nothing else, because nothing announces it.
            addresses = [ { Address = "${clientBehind}/128"; } ];
          };
          networks."40-ranet0" = {
            matchConfig.Name = "ranet0";
            linkConfig = {
              MTUBytes = 1400;
              RequiredForOnline = false;
            };
            networkConfig.ConfigureWithoutCarrier = true;
            addresses = [
              { Address = "${clientTunnel}/128"; }
              { Address = "${clientTunnelV4}/32"; }
            ];
            routes = [
              { Destination = "fd00:99::/64"; }
              { Destination = "10.99.0.0/24"; }
            ];
          };
        };

        environment.etc = {
          "ranet-lite/key.pem".source = ./org-key.pem;
          "ranet-lite/registry.json".text = builtins.toJSON [
            {
              public_key = publicKey;
              organization = "testorg";
              nodes = [
                {
                  common_name = "client";
                  endpoints = [
                    {
                      serial_number = "2";
                      address_family = "ip4";
                      address = nodes.client.networking.primaryIPAddress;
                      port = 14000;
                    }
                  ];
                  remarks = { };
                }
                {
                  common_name = "server";
                  endpoints = [
                    {
                      serial_number = "1";
                      address_family = "ip4";
                      address = nodes.gateway.networking.primaryIPAddress;
                      port = 13000;
                    }
                  ];
                  remarks = { };
                }
              ];
            }
          ];
          "ranet-lite/config.yaml".text = ''
            organization: testorg
            common_name: client
            port: 14000
            endpoints:
              - serial_number: "2"
                address_family: ip4
            private_key: /etc/ranet-lite/key.pem
            registry: /etc/ranet-lite/registry.json
            originate:
              - "${clientTunnel}/128"
              - "${clientTunnelV4}/32"
            ${pkgs.lib.optionalString segments "  - \"${clientSID}/128\"\n"}
            tun: ranet0
            child_rekey_interval: ${if profile then "0" else "5s"}
            ike_rekey_interval: ${if profile then "0" else "15s"}
            rekey_margin: 0
            rekey_jitter: 0
            ${
              if responder then
                "responder: true"
              else
                ''
                  peers:
                    - common_name: server
                      serial_number: "1"
                ''
            }
            ${pkgs.lib.optionalString segments ''
              segments:
                source: "${clientTunnel}"
                local:
                  - { sid: "${clientSID}", behavior: "End.DT46" }
                steer:
                  - from: "${clientTunnel}/128"
                    to: "${gatewayBehind}/128"
                    via: ["${gatewaySID}"]
            ''}
            ${pkgs.lib.optionalString kernel ''
              kernel:
                enabled: true
                table: ${toString kernelTable}
                protocol: ${toString kernelProtocol}
                metric: 32
                prefsrc4: ${clientTunnelV4}
                reconcile_interval: 2s
            ''}
            babel:
              hello_interval: 500ms
              update_interval: 1s
          '';
        };

        systemd.services.ranet-lite = {
          description = "Ranet-lite integration-test client";
          wantedBy = [ "multi-user.target" ];
          wants = [ "network-online.target" ];
          after = [ "network-online.target" ];
          serviceConfig = {
            ExecStart =
              "${ranetLite}/bin/ranet-lite daemon --config /etc/ranet-lite/config.yaml --log-level debug --metrics 127.0.0.1:9669"
              + pkgs.lib.optionalString profile " -pprof 127.0.0.1:6060";
            TimeoutStopSec = "15s";
            Restart = "on-failure";
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
          };
        };
      };
  };

  testScript =
    let
      preamble = ''
        import datetime as dt

        timeout = dt.timedelta(seconds=30)

        kernel_enabled = ${if kernel then "True" else "False"}
        kernel_table = "${toString kernelTable}"
        kernel_protocol = "${toString kernelProtocol}"
        client_tunnel_v4 = "${clientTunnelV4}"

        def journal_after(machine, unit):
            output = machine.succeed(f"journalctl -u {unit} -n 1 --show-cursor --no-pager")
            cursor = output.rsplit("-- cursor: ", 1)[1].strip()
            return f"journalctl -u {unit} --after-cursor='{cursor}' --no-pager"

        start_all()

      '';

      # The gateway's own kernel decapsulates what this tree encapsulated, so
      # the header is checked against the implementation it interoperates with
      # rather than against its own decoder.
      #
      # The assertion is on the capture rather than on a round trip, because
      # what is being tested is whether the kernel accepts this tree's header
      # and takes it off. Where the inner packet goes afterwards is the test
      # topology's business: End.DT6 looks the decapsulated destination up in
      # the table it is given, and a local address of the gateway's is not in
      # main.
      segmentRouted = ''
        import json

        gateway.wait_for_unit("systemd-networkd-wait-online.service")
        gateway.wait_for_unit("strongswan-swanctl.service")
        gateway.wait_for_unit("bird.service")
        client.wait_for_unit("ranet-lite.service")

        # The unsteered path first, so a failure below is the segment rather
        # than the mesh.
        client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

        # The local SID is the kernel's own behavior, added here rather than
        # in the module so a rejection is a failing command. The device is the
        # one the packet arrives on: an input lookup landing on a route out of
        # lo answers ICMP unreachable, which reads exactly like a segment the
        # kernel never had.
        gateway.succeed(
            "ip -6 route replace ${gatewaySID}/128 encap seg6local action End.DT6 table 254 dev swan0"
        )
        print(gateway.succeed("ip -6 route show ${gatewaySID}/128"))

        def steer_and_capture(machine, name):
            """Three steered packets, and what the gateway made of them."""
            machine.succeed(f"rm -f /tmp/{name}.pcap")
            machine.execute(f"tcpdump -ni swan0 -w /tmp/{name}.pcap ip6 >/dev/null 2>&1 &")
            machine.wait_until_succeeds("pgrep -x tcpdump", timeout=timeout)
            client.execute("ping -c 3 -i 0.3 -W 1 -I ${clientTunnel} ${gatewayBehind}")
            machine.succeed("pkill -x tcpdump")
            machine.wait_until_fails("pgrep -x tcpdump", timeout=timeout)
            return machine.succeed(f"tcpdump -nr /tmp/{name}.pcap 'not port 6696'")

        def bare_inner(capture):
            """The inner packet on its own, with no routing header left.

            The encapsulated line carries the inner addresses too, since
            tcpdump prints what is inside, so the routing header is the only
            thing telling the two apart. The ICMP error the gateway sends when it has no
            segment runs the other way and matches neither.
            """
            return [
                line for line in capture.splitlines()
                if "${clientTunnel} > ${gatewayBehind}:" in line and "RT6" not in line
            ]

        carried = steer_and_capture(gateway, "carried")
        print(carried)
        # The encapsulated packet arrived, addressed to the segment.
        assert "${gatewaySID}" in carried, "the steered packet never reached the gateway"
        # And the kernel took the header off.
        assert bare_inner(carried), f"the kernel did not decapsulate this tree's header:\n{carried}"

        status = json.loads(client.succeed("ranet-lite status --json"))
        print(json.dumps(status["segment_counters"], indent=2))
        assert status["segment_counters"]["steered"] > 0, "nothing was steered"
        assert status["segment_counters"]["unsteered"] == 0, "a packet could not be steered"
        assert status["steering"], "the steering policy is not reported"

        # Taking the segment away leaves the encapsulated packet arriving and
        # nothing coming out of it, which is the proof that the line above was
        # the kernel acting on the header rather than anything else.
        gateway.succeed("ip -6 route del ${gatewaySID}/128")
        refused = steer_and_capture(gateway, "refused")
        print(refused)
        assert "${gatewaySID}" in refused, "the steered packet stopped arriving for another reason"
        assert not bare_inner(refused), f"something still decapsulated the header:\n{refused}"

        # The other direction: the gateway's kernel builds the header and this
        # tree acts on it. Nothing announces the address behind the client, so
        # the gateway reaches it through the segment or not at all, and the
        # client's own counter says which of the two carried the packet.
        gateway.wait_until_succeeds("ip -6 route get ${clientSID}", timeout=timeout)
        gateway.succeed(
            "ip -6 route replace ${clientBehind}/128 encap seg6 mode encap segs ${clientSID} dev swan0"
        )
        print(gateway.succeed("ip -6 route show ${clientBehind}/128"))

        before = json.loads(client.succeed("ranet-lite status --json"))["segment_counters"]
        gateway.wait_until_succeeds(
            "ping -c 1 -W 2 -I ${gatewayTunnel} ${clientBehind}", timeout=timeout
        )
        gateway.succeed("ping -c 3 -i 0.3 -W 2 -I ${gatewayTunnel} ${clientBehind}")
        status = json.loads(client.succeed("ranet-lite status --json"))
        after = status["segment_counters"]
        print(json.dumps(after, indent=2))
        assert after["delivered"] > before["delivered"], (
            f"the ping arrived without this tree's exit delivering it: {before} then {after}"
        )
        assert after["dropped"] == before["dropped"], f"a segment was refused: {after}"
        assert status["segments"], "the local segment is not reported"
      '';

      # strongSwan answers, ranet-lite dials: upstream's original exchange.
      initiator = ''
        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            gateway.wait_for_unit("iperf3.service")
            client.wait_for_unit("ranet-lite.service")

            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnelV4}", timeout=timeout)
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --child default"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'parsed CREATE_CHILD_SA response.*SA No KE TSi TSr'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --ike ranet"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'IKE_SA ranet.* rekeyed between'", timeout=timeout)
            local_rekeys = journal_after(client, "ranet-lite.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            profile = ${if profile then "True" else "False"}
            if profile:
                # NixOS tests force acpi_pm for deterministic timekeeping. Its
                # virtual I/O reads dominate CPU profiles, so use the KVM clock
                # in this performance-only variant on both sides of the tunnel.
                for machine in [client, gateway]:
                    machine.succeed("echo kvm-clock > /sys/devices/system/clocksource/clocksource0/current_clocksource")
                    assert machine.succeed("cat /sys/devices/system/clocksource/clocksource0/current_clocksource").strip() == "kvm-clock"
            duration = 25 if profile else 5
            for direction, flags in [("outbound", ""), ("inbound", "--reverse"), ("bidir", "--bidir")]:
                if profile:
                    client.succeed(f"systemd-run --unit=ranet-{direction}-profile --collect curl --silent --show-error 'http://127.0.0.1:6060/debug/pprof/profile?seconds=20' --output /tmp/{direction}.pprof")
                    pid = client.succeed("systemctl show -p MainPID --value ranet-lite.service").strip()
                    client.succeed(f"systemd-run --unit=ranet-{direction}-kernel-profile --collect perf record -e cpu-clock:k -F 199 -g -p {pid} -o /tmp/{direction}.perf -- sleep 20")
                # iperf3's server closes and reopens its listening socket between
                # tests, so a client that connects in that window is refused.
                # Retrying keeps a harness race out of the result, while a peer
                # that is genuinely unreachable still fails once they run out.
                print(client.wait_until_succeeds(
                    f"iperf3 --client ${gatewayTunnel} --parallel 8 --time {duration} {flags}",
                    timeout=120,
                ))
                if profile:
                    client.wait_until_succeeds(f"test -s /tmp/{direction}.pprof")
                    print(client.succeed(f"pprof -top -nodecount=50 /tmp/{direction}.pprof"))
                    print(client.succeed(f"perf report --stdio --no-children --percent-limit 1 -g none -i /tmp/{direction}.perf"))
                    client.copy_from_machine(f"/tmp/{direction}.pprof")
                    client.copy_from_machine(f"/tmp/{direction}.perf")

            if not profile:
                # Verify both new IKE keys and subsequent ESP keys are usable.
                # swanctl's exit status alone does not prove a rekey succeeded.
                for sa in ["Child SA", "IKE SA"]:
                    client.wait_until_succeeds(f"{local_rekeys} | grep -F 'ike scheduled rekey completed' | grep -F 'sa=\"{sa}\"'", timeout=timeout)
                client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            # A graceful BIRD stop retracts routes, then fresh announcements restore
            # them without reconnecting IKE. Check the client publication as well as IP.
            withdrawal = journal_after(client, "ranet-lite.service")
            gateway.succeed("systemctl stop bird.service")
            client.wait_until_succeeds(f"{withdrawal} | grep -F 'babel route retracted'", timeout=timeout)
            gateway.succeed("systemctl start bird.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnelV4}", timeout=timeout)
            if kernel_enabled:
                # What replaces kbabel4 and kbabel6 on a fleet node: a route babel
                # learned has to be in the kernel table the policy rules look up,
                # carrying this reconciler's protocol and the configured prefsrc.
                client.wait_until_succeeds(f"ip -4 route show table {kernel_table} | grep -q '10.99.0.0/24'", timeout=timeout)
                client.wait_until_succeeds(f"ip -6 route show table {kernel_table} | grep -q 'fd00:99::/64'", timeout=timeout)
                v4 = client.succeed(f"ip -4 route show table {kernel_table}")
                v6 = client.succeed(f"ip -6 route show table {kernel_table}")
                print(v4)
                print(v6)
                assert f"proto {kernel_protocol}" in v4, v4
                assert f"src {client_tunnel_v4}" in v4, v4
                assert "dev ranet0" in v4, v4
                # The main table is not this reconciler's to write.
                leaked = client.succeed(f"ip -4 route show proto {kernel_protocol}")
                assert "10.99.0.0/24" not in leaked, leaked
            # The endpoint that replaces prometheus-bird-exporter has to report a
            # live neighbor and a selected route, not just answer.
            client.wait_until_succeeds("curl -sf http://127.0.0.1:9669/metrics | grep -q '^ranet_lite_babel_neighbor_up{.*} 1$'", timeout=timeout)
            metrics = client.succeed("curl -sf http://127.0.0.1:9669/metrics")
            print(metrics)
            assert "ranet_lite_sessions 1" in metrics, metrics
            assert "ranet_lite_babel_routes_originated 2" in metrics, metrics
            selected = [line for line in metrics.splitlines() if line.startswith("ranet_lite_babel_routes_selected ")]
            assert selected and int(selected[0].split()[1]) > 0, metrics

            assert client.succeed("journalctl -u ranet-lite.service --no-pager | grep -c ': connected (SPI'").strip() == "1"
            client.fail("journalctl -u ranet-lite.service --no-pager | grep -F 'no matching inbound ESP SA'")
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built'")

            # Closing an idle TUN read must stop promptly without SIGKILL.
            client.succeed("systemctl stop ranet-lite.service")
            assert client.succeed("systemctl show -p Result --value ranet-lite.service").strip() == "success"
            if kernel_enabled:
                # Shutdown withdraws what it installed rather than leaving it behind.
                assert client.succeed(f"ip -4 route show table {kernel_table}").strip() == "", "ipv4 routes survived shutdown"
                assert client.succeed(f"ip -6 route show table {kernel_table}").strip() == "", "ipv6 routes survived shutdown"
            client.succeed("systemctl start ranet-lite.service")
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
        finally:
            for command in ["swanctl --list-sas", "birdc show babel neighbors", "birdc show babel routes"]:
                print(gateway.execute(command)[1])
      '';

      # strongSwan dials, ranet-lite answers.
      responderScript = ''
        try:
            gateway.wait_for_unit("systemd-networkd-wait-online.service")
            gateway.wait_for_unit("strongswan-swanctl.service")
            gateway.wait_for_unit("bird.service")
            client.wait_for_unit("ranet-lite.service")

            # ranet-lite has no peers configured here, so it never dials. A tunnel
            # exists only if it answered strongSwan's IKE_SA_INIT.
            client.fail("journalctl -u ranet-lite.service --no-pager | grep -F ': dialing '")
            gateway.succeed("swanctl --initiate --child default")
            client.wait_until_succeeds("journalctl -u ranet-lite.service --no-pager | grep -F ': connected (SPI'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnelV4}", timeout=timeout)

            # The peer drives both rekeys. An answered session has to service them
            # exactly as a dialed one does, from the opposite role.
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --child default"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'parsed CREATE_CHILD_SA response.*SA No KE TSi TSr'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            peer_rekey = journal_after(gateway, "strongswan-swanctl.service")
            print(gateway.succeed("swanctl --rekey --ike ranet"))
            gateway.wait_until_succeeds(f"{peer_rekey} | grep -E 'IKE_SA ranet.* rekeyed between'", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)

            client.fail("journalctl -u ranet-lite.service --no-pager | grep -F 'no matching inbound ESP SA'")
            gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built'")

            # Losing the answered SA has to be recoverable without ranet-lite ever
            # dialing, so the responder accepts a second SA for a peer it already
            # knew. Drive the peer rather than waiting out its DPD timers: what is
            # under test is the responder, not how long charon takes to notice.
            client.succeed("systemctl restart ranet-lite.service")
            gateway.execute("swanctl --terminate --ike ranet")
            gateway.wait_until_succeeds("swanctl --initiate --child default", timeout=timeout)
            client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
            client.fail("journalctl -u ranet-lite.service --no-pager | grep -F ': dialing '")
        finally:
            for command in [
                "swanctl --list-sas",
                "birdc show babel neighbors",
                "birdc show babel routes",
                "ip xfrm state",
                "ip xfrm policy",
                "grep -v ' 0$' /proc/net/xfrm_stat",
                "ip -s link show swan0",
            ]:
                print(gateway.execute(command)[1])
            print(client.execute("ip -s link show ranet0")[1])
      '';
    in
    preamble
    + (
      if responder then
        responderScript
      else if segments then
        segmentRouted
      else
        initiator
    );
}
