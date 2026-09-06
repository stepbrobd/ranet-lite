{
  pkgs,
  ranetLite,
  cores ? 1,
  profile ? false,
}:

let
  gatewayTunnel = "fd00:99::1";
  clientTunnel = "fd00:88::2";
  gatewayTunnelV4 = "10.99.0.1";
  clientTunnelV4 = "10.88.0.2";
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
  name = "ranet-lite-integration";

  nodes = {
    gateway =
      { config, ... }:
      {
        imports = [ common ];

        boot.kernelModules = [ "xfrm_interface" ];
        environment.systemPackages = with pkgs; [
          bird2
          iperf3
          iproute2
          config.services.strongswan-swanctl.package
        ];

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
              ];
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
              remote_addrs = [ "0.0.0.0/0" ];
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
                rxcost 32;
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
            iperf3
            iproute2
          ]
          ++ lib.optionals profile [
            curl
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
            tun: ranet0
            child_rekey_interval: ${if profile then "0" else "5s"}
            ike_rekey_interval: ${if profile then "0" else "15s"}
            rekey_margin: 0
            rekey_jitter: 0
            peers:
              - common_name: server
                serial_number: "1"
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
              "${ranetLite}/bin/ranet-lite -config /etc/ranet-lite/config.yaml -log-level debug"
              + pkgs.lib.optionalString profile " -pprof 127.0.0.1:6060";
            TimeoutStopSec = "15s";
            Restart = "on-failure";
            AmbientCapabilities = [ "CAP_NET_ADMIN" ];
            CapabilityBoundingSet = [ "CAP_NET_ADMIN" ];
          };
        };
      };
  };

  testScript = ''
    import datetime as dt

    timeout = dt.timedelta(seconds=30)

    def journal_after(machine, unit):
        output = machine.succeed(f"journalctl -u {unit} -n 1 --show-cursor --no-pager")
        cursor = output.rsplit("-- cursor: ", 1)[1].strip()
        return f"journalctl -u {unit} --after-cursor='{cursor}' --no-pager"

    start_all()

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
            print(client.succeed(f"iperf3 --client ${gatewayTunnel} --parallel 8 --time {duration} {flags}"))
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
        assert client.succeed("journalctl -u ranet-lite.service --no-pager | grep -c ': connected (SPI'").strip() == "1"
        client.fail("journalctl -u ranet-lite.service --no-pager | grep -F 'no matching inbound ESP SA'")
        gateway.fail("journalctl -u strongswan-swanctl.service --no-pager | grep -E 'integrity check failed|no CHILD_SA built'")

        # Closing an idle TUN read must stop promptly without SIGKILL.
        client.succeed("systemctl stop ranet-lite.service")
        assert client.succeed("systemctl show -p Result --value ranet-lite.service").strip() == "success"
        client.succeed("systemctl start ranet-lite.service")
        client.wait_until_succeeds("ping -c 1 ${gatewayTunnel}", timeout=timeout)
    finally:
        for command in ["swanctl --list-sas", "birdc show babel neighbors", "birdc show babel routes"]:
            print(gateway.execute(command)[1])
  '';
}
