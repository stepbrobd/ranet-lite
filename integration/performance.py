#!/usr/bin/env python3
"""Run only inside unshare --user --map-root-user --mount --net.

The client and the peer communicate over a private veth pair. The peer owns a
second network namespace and is either a Linux/strongSwan gateway or, under
--peer ranet-lite, a second ranet-lite instance answering as a responder. No
host interfaces or services are modified. Logs and profiles remain in --output
after processes exit.
"""

import argparse
import concurrent.futures
import hashlib
import json
import os
import shutil
import subprocess
import time
import urllib.request
from pathlib import Path

parser = argparse.ArgumentParser()
parser.add_argument("--client", required=True, type=Path)
parser.add_argument("--output", required=True, type=Path)
parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
parser.add_argument("--cores", type=int, default=6)
parser.add_argument("--duration", type=int, default=15)
parser.add_argument("--streams", type=int, default=8)
parser.add_argument("--directions", default="bidir")
parser.add_argument("--gro", choices=["on", "off"])
parser.add_argument("--delay", default=None)
parser.add_argument("--protocol", choices=["tcp", "udp"], default="tcp")
parser.add_argument(
    "--rate", type=float, default=10, help="aggregate UDP Gbit/s per direction"
)
parser.add_argument(
    "--replay-window",
    type=int,
    default=4096,
    help="strongSwan Child SA window, matched to ranet-lite's own default so "
    "the two arms are compared at the same window rather than 32 against 4096",
)
parser.add_argument("--affinity")
parser.add_argument(
    "--peer", choices=["strongswan", "ranet-lite"], default="strongswan"
)
parser.add_argument("--peer-affinity")
parser.add_argument("--peer-cores", type=int)
parser.add_argument("--client-port", type=int, default=20000)
args = parser.parse_args()
ranet_peer = args.peer == "ranet-lite"


def cpu_list(spec):
    # taskset's own list syntax, parsed here so a typo fails before the run
    # rather than as a pinned process that exits during startup.
    selected = set()
    for part in spec.split(","):
        bounds = part.split("-")
        if len(bounds) > 2 or not all(bound.isdigit() for bound in bounds):
            parser.error(f"invalid cpu list {spec!r}")
        selected.update(range(int(bounds[0]), int(bounds[-1]) + 1))
    if not selected:
        parser.error(f"invalid cpu list {spec!r}")
    return selected


if args.cores < 1 or args.duration < 1 or args.streams < 1 or args.rate < 0:
    parser.error(
        "cores, duration, and streams must be positive; rate must be nonnegative"
    )
if not ranet_peer and (args.peer_affinity or args.peer_cores):
    parser.error("--peer-affinity and --peer-cores require --peer ranet-lite")
if args.peer_cores is not None and args.peer_cores < 1:
    parser.error("peer-cores must be positive")
pinned = [cpu_list(spec) for spec in [args.affinity, args.peer_affinity] if spec]
if len(pinned) == 2 and pinned[0] & pinned[1]:
    # Both instances on one cpu measures how they contend, not the dataplane.
    parser.error(
        f"--affinity and --peer-affinity share cpus {sorted(pinned[0] & pinned[1])}"
    )
if any(
    direction not in {"bidir", "outbound", "inbound"}
    for direction in args.directions.split(",")
):
    parser.error(
        "directions must be a comma-separated list of outbound, inbound, or bidir"
    )
uid_map = Path("/proc/self/uid_map").read_text().split()
if (
    os.geteuid() != 0
    or len(uid_map) != 3
    or uid_map[0] != "0"
    or uid_map[1] == "0"
    or uid_map[2] != "1"
):
    parser.error(
        "run with unshare --user --map-root-user --mount --net as an ordinary user"
    )
args.client, args.repo, args.output = (
    args.client.resolve(),
    args.repo.resolve(),
    args.output.resolve(),
)
if not args.client.is_file():
    parser.error(f"client binary does not exist: {args.client}")
commands = {}
for name in [
    "ip",
    "mount",
    "unshare",
    "nsenter",
    "sleep",
    "cat",
    "bird",
    "charon-systemd",
    "swanctl",
    "ping",
    "tc",
    "taskset",
    "iperf3",
    "ethtool",
]:
    executable = shutil.which(name)
    if executable is None:
        parser.error(f"required program {name!r} is missing; use nix develop")
    commands[name] = str(Path(executable).resolve())
for name in ["sleep", "cat"]:
    # Preserve argv[0] for coreutils' multicall binary.
    commands[name] = str(Path(commands[name]).parent / name)
# NixOS may expose mount through a security wrapper. Use the util-linux
# executable directly: privileges come only from the private user namespace.
mount = Path(commands["unshare"]).parent / "mount"
if mount.exists():
    commands["mount"] = str(mount)
args.output.mkdir(parents=True, exist_ok=False)
with args.client.open("rb") as binary:
    client_hash = hashlib.file_digest(binary, "sha256").hexdigest()
(args.output / "metadata.json").write_text(
    json.dumps(
        {
            "arguments": vars(args),
            "kernel": os.uname().release,
            "client_sha256": client_hash,
            "iperf3": {
                "executable": commands["iperf3"],
                "version": subprocess.run(
                    [commands["iperf3"], "--version"],
                    check=True,
                    capture_output=True,
                    text=True,
                ).stdout,
            },
            "cpu_model": next(
                (
                    line.split(":", 1)[1].strip()
                    for line in Path("/proc/cpuinfo").read_text().splitlines()
                    if line.startswith("model name")
                ),
                "unknown",
            ),
        },
        indent=2,
        default=str,
    )
    + "\n"
)
processes = []
# Every instance serves pprof and metrics. The client answers on its own
# loopback; the peer answers over a management veth kept off the data path, so
# no scrape shares the link under measurement.
client_pprof, client_metrics = "127.0.0.1:6060", "127.0.0.1:9669"
peer_pprof, peer_metrics = "10.201.0.2:6061", "10.201.0.2:9670"
instances = [("client", client_pprof, client_metrics)]
if ranet_peer:
    instances.append(("peer", peer_pprof, peer_metrics))


def run(command, gateway=False, check=True, **kwargs):
    command = [commands.get(str(command[0]), str(command[0]))] + [
        str(v) for v in command[1:]
    ]
    if gateway:
        command = [commands["nsenter"], "-t", str(ns.pid), "-n"] + command
    return subprocess.run(
        command,
        check=check,
        text=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        **kwargs,
    )


def start(command, name, gateway=False, env=None):
    command = [commands.get(str(command[0]), str(command[0]))] + [
        str(v) for v in command[1:]
    ]
    if gateway:
        command = [commands["nsenter"], "-t", str(ns.pid), "-n"] + command
    with (args.output / (name + ".log")).open("w") as log:
        proc = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, env=env)
    processes.append(proc)
    return proc


def wait_for(test, message, timeout=15):
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        try:
            if test():
                return
        except FileNotFoundError:
            pass
        for proc in processes:
            if proc.poll() is not None:
                raise RuntimeError(
                    f"process {proc.args} exited with {proc.returncode}; see {args.output}"
                )
        time.sleep(0.1)
    raise RuntimeError(message)


# The client keeps the unsuffixed artifact names the strongSwan mode has always
# written, so one output directory reads the same way in both modes.
def suffix(name):
    return "" if name == "client" else "-" + name


def scrape(address):
    with urllib.request.urlopen(f"http://{address}/metrics", timeout=5) as response:
        return response.read().decode()


def sample(text, metric):
    # Sums every series of one metric, so a per-neighbor gauge reduces to the
    # count of live neighbors and a bare gauge returns itself. A metric the
    # exporter never wrote reads as None rather than as zero.
    total, found = 0.0, False
    for line in text.splitlines():
        series, _, value = line.rpartition(" ")
        if line.startswith("#") or not (
            series == metric or series.startswith(metric + "{")
        ):
            continue
        total, found = total + float(value), True
    return total if found else None


def babel_state(text):
    # The four numbers that separate a converged mesh from a degraded one.
    return {
        "sessions": sample(text, "ranet_lite_sessions"),
        "neighbors": sample(text, "ranet_lite_babel_neighbor_up"),
        "routes_selected": sample(text, "ranet_lite_babel_routes_selected"),
        "routes_originated": sample(text, "ranet_lite_babel_routes_originated"),
    }


def profile(direction, name, address):
    url = f"http://{address}/debug/pprof/profile?seconds={args.duration}"
    with urllib.request.urlopen(url, timeout=args.duration + 10) as response:
        (args.output / (direction + suffix(name) + ".pprof")).write_bytes(
            response.read()
        )


def sample_state(direction):
    time.sleep(args.duration / 2)
    for name, address, metrics in instances:
        with urllib.request.urlopen(
            f"http://{address}/debug/pprof/goroutine?debug=2", timeout=5
        ) as response:
            (args.output / (direction + suffix(name) + "-goroutines.txt")).write_bytes(
                response.read()
            )
        if ranet_peer:
            (args.output / (direction + suffix(name) + "-metrics.txt")).write_text(
                scrape(metrics)
            )
    (args.output / (direction + "-links.txt")).write_text(
        run(["ip", "-s", "link"]).stdout
    )
    (args.output / (direction + "-udp.txt")).write_text(
        run(["cat", "/proc/net/snmp"]).stdout
    )
    for side, gateway in [("client", False), ("gateway", True)]:
        (args.output / f"{direction}-{side}-packet-sockets.txt").write_text(
            run(["cat", "/proc/net/packet"], gateway=gateway).stdout
        )


def traffic(label, address, flags, collect_profile=False):
    print(
        f"Starting {label}: cores={args.cores}, streams={args.streams}, seconds={args.duration}",
        flush=True,
    )
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(instances) + 1) as pool:
        pending = []
        if collect_profile:
            pending = [
                pool.submit(profile, label, name, address)
                for name, address, _ in instances
            ]
            pending.append(pool.submit(sample_state, label))
        if args.protocol == "udp":
            flags = flags + [
                "--udp",
                "--gsro",
                "-w",
                "4M",
                "-l",
                "1300",
                "-b",
                str(int(args.rate * 1e9 / args.streams)),
            ]
        port = (
            args.client_port
            + {"plain-bidir": 0, "outbound": 100, "inbound": 200, "bidir": 300}[label]
        )
        flags = flags + ["--cport", str(port)]
        result = run(
            ["iperf3", "-c", address, "-P", args.streams, "-t", args.duration, "--json"]
            + flags,
            check=False,
            timeout=args.duration + 15,
        )
        (args.output / (label + ".json")).write_text(result.stdout)
        if result.returncode:
            raise RuntimeError(result.stdout)
        data = json.loads(result.stdout)
        summary = {
            key: value
            for key, value in data.get("end", {}).items()
            if key.startswith("sum_")
        }
        print(
            json.dumps({"label": label, "end": summary, "error": data.get("error")}),
            flush=True,
        )
        for future in pending:
            future.result()


try:
    # Isolate daemon PID/socket files as well as networking. All executable
    # paths were resolved before hiding the host's /run/current-system link.
    run(["mount", "-t", "tmpfs", "tmpfs", "/run"])
    ns = start(["unshare", "--net", commands["sleep"], "infinity"], "namespace")
    wait_for(
        lambda: (
            os.readlink(f"/proc/{ns.pid}/ns/net") != os.readlink("/proc/self/ns/net")
        ),
        "gateway namespace did not start",
    )
    client_links = [
        ["ip", "link", "set", "lo", "up"],
        ["ip", "link", "add", "client0", "type", "veth", "peer", "name", "gateway0"],
        ["ip", "link", "set", "gateway0", "netns", ns.pid],
        ["ip", "addr", "add", "10.200.0.1/30", "dev", "client0"],
        ["ip", "link", "set", "client0", "up"],
    ]
    gateway_links = [
        ["ip", "link", "set", "lo", "up"],
        ["ip", "addr", "add", "10.200.0.2/30", "dev", "gateway0"],
        ["ip", "link", "set", "gateway0", "up"],
    ]
    # A second veth pair carries pprof and metrics only, so scraping the peer
    # never shares the link the benchmark is measuring.
    manage_client = [
        ["ip", "link", "add", "manage0", "type", "veth", "peer", "name", "manage1"],
        ["ip", "link", "set", "manage1", "netns", ns.pid],
        ["ip", "addr", "add", "10.201.0.1/30", "dev", "manage0"],
        ["ip", "link", "set", "manage0", "up"],
    ]
    manage_gateway = [
        ["ip", "addr", "add", "10.201.0.2/30", "dev", "manage1"],
        ["ip", "link", "set", "manage1", "up"],
    ]
    # swan0 is strongSwan's half of the tunnel. A ranet-lite peer terminates
    # ESP in userspace and creates its own TUN instead.
    swan_links = [
        ["ip", "link", "add", "swan0", "type", "xfrm", "dev", "gateway0", "if_id", "1"],
        ["ip", "link", "set", "swan0", "mtu", "1400", "multicast", "on", "up"],
        ["ip", "addr", "add", "fe80::1/64", "dev", "swan0", "nodad"],
        ["ip", "addr", "add", "fd00:99::1/64", "dev", "swan0", "nodad"],
    ]
    for command in client_links + (manage_client if ranet_peer else []):
        run(command)
    for command in gateway_links + (manage_gateway if ranet_peer else swan_links):
        run(command, gateway=True)
    for interface, gateway in [("client0", False), ("gateway0", True)]:
        if args.delay:
            run(
                [
                    "tc",
                    "qdisc",
                    "add",
                    "dev",
                    interface,
                    "root",
                    "netem",
                    "delay",
                    args.delay,
                    "limit",
                    "100000",
                ],
                gateway=gateway,
            )
        if args.gro:
            run(["ethtool", "-K", interface, "gro", args.gro], gateway=gateway)
        (args.output / (interface + "-offloads.txt")).write_text(
            run(["ethtool", "-k", interface], gateway=gateway).stdout
        )
    if not ranet_peer:
        swan_dir = args.output / "swanctl"
        for directory in [
            "x509",
            "x509ca",
            "x509ocsp",
            "x509aa",
            "x509ac",
            "x509crl",
            "rsa",
            "ecdsa",
            "pkcs8",
            "pkcs12",
        ]:
            (swan_dir / directory).mkdir(parents=True, exist_ok=True)
        for directory, fixture in [
            ("private", "org-key.pem"),
            ("pubkey", "org-pub.pem"),
        ]:
            (swan_dir / directory).mkdir(parents=True, exist_ok=True)
            shutil.copyfile(
                args.repo / "integration" / fixture, swan_dir / directory / fixture
            )
        swan_conf = swan_dir / "swanctl.conf"
        swan_conf.write_text("""connections {
  ranet {
    version = 2
    local_addrs = 10.200.0.2
    remote_addrs = 10.200.0.1
    local_port = 13000
    remote_port = 14000
    encap = yes
    mobike = no
    if_id_in = 1
    if_id_out = 1
    local {
      auth = pubkey
      pubkeys = org-pub.pem
      id = "O=testorg, CN=server, serialNumber=1"
    }
    remote {
      auth = pubkey
      pubkeys = org-pub.pem
      id = "O=testorg, CN=client, serialNumber=2"
    }
    children {
      default {
        local_ts = 0.0.0.0/0, ::/0
        remote_ts = 0.0.0.0/0, ::/0
        mode = tunnel
      }
    }
  }
}
""")
        swan_conf.write_text(
            swan_conf.read_text().replace(
                "        mode = tunnel",
                f"        replay_window = {args.replay_window}\n        mode = tunnel",
            )
        )
        strong_conf = args.output / "strongswan.conf"
        strong_conf.write_text(
            """charon-systemd {
  port = 0
  port_nat_t = 13000
  install_routes = no
  plugins {
    vici { socket = unix:///run/charon.vici }
    kernel-netlink { install_routes = no }
  }
  journal { default = -1 }
  filelog {
    stdout { default = 1; flush_line = yes }
  }
}
""".replace("; flush_line", "\n      flush_line")
        )
        env = dict(
            os.environ, STRONGSWAN_CONF=str(strong_conf), SWANCTL_DIR=str(swan_dir)
        )
        start(["charon-systemd"], "strongswan", gateway=True, env=env)
        wait_for(
            lambda: Path("/run/charon.vici").exists(),
            "strongSwan did not create its private VICI socket",
        )
        print(
            run(
                [
                    "swanctl",
                    "--load-all",
                    "--file",
                    swan_conf,
                    "--uri",
                    "unix:///run/charon.vici",
                ],
                gateway=True,
                env=env,
            ).stdout,
            flush=True,
        )
        bird_conf = args.output / "bird.conf"
        bird_conf.write_text("""log stderr all;
router id 10.200.0.2;
ipv6 sadr table sadr6;
protocol device { scan time 1; }
protocol kernel { ipv6 sadr { export all; import none; }; }
protocol static { ipv6 sadr; route fd00:99::/64 from ::/0 unreachable; }
protocol babel {
  ipv6 sadr { export all; import all; };
  interface "swan0" {
    type tunnel;
    rxcost 96;
    hello interval 500 ms;
    update interval 1 s;
    rx buffer 1500;
  };
}
""")
        start(
            [
                "bird",
                "-f",
                "-c",
                bird_conf,
                "-s",
                "/run/bird.ctl",
                "-P",
                "/run/bird.pid",
            ],
            "bird",
            gateway=True,
        )
    start(["iperf3", "-s"], "iperf-server", gateway=True)
    public = (args.repo / "integration/org-pub.pem").read_text()
    registry = args.output / "registry.json"
    registry.write_text(
        json.dumps(
            [
                {
                    "organization": "testorg",
                    "public_key": public,
                    "nodes": [
                        {
                            "common_name": "client",
                            "endpoints": [
                                {
                                    "serial_number": "2",
                                    "address_family": "ip4",
                                    "address": "10.200.0.1",
                                    "port": 14000,
                                }
                            ],
                        },
                        {
                            "common_name": "server",
                            "endpoints": [
                                {
                                    "serial_number": "1",
                                    "address_family": "ip4",
                                    "address": "10.200.0.2",
                                    "port": 13000,
                                }
                            ],
                        },
                    ],
                }
            ]
        )
    )
    if ranet_peer:
        # The same registry and organization key, a second identity, and no
        # peers list: this instance only answers. Its tunnel addresses are
        # swan0's, so both modes measure the same path between the same two
        # endpoints.
        peer_conf = args.output / "peer.yaml"
        peer_conf.write_text(f"""organization: testorg
common_name: server
port: 13000
endpoints:
  - serial_number: "1"
    address_family: ip4
private_key: {args.repo / "integration/org-key.pem"}
registry: {registry}
originate: ["fd00:99::/64"]
tun: ranet1
child_rekey_interval: 0
ike_rekey_interval: 0
responder: true
babel:
  hello_interval: 500ms
  update_interval: 1s
""")
        peer_command = [
            str(args.client),
            "-config",
            peer_conf,
            "-pprof",
            peer_pprof,
            "-metrics",
            peer_metrics,
        ]
        if args.peer_affinity:
            peer_command = ["taskset", "-c", args.peer_affinity] + peer_command
        start(
            peer_command,
            "peer",
            gateway=True,
            env=dict(os.environ, GOMAXPROCS=str(args.peer_cores or args.cores)),
        )
        wait_for(
            lambda: (
                run(
                    ["ip", "link", "show", "ranet1"], gateway=True, check=False
                ).returncode
                == 0
            ),
            "peer did not create TUN",
        )
        for command in [
            ["ip", "addr", "add", "fd00:99::1/64", "dev", "ranet1", "nodad"],
            ["ip", "route", "add", "fd00:88::2/128", "dev", "ranet1"],
        ]:
            run(command, gateway=True)
    client_conf = args.output / "client.yaml"
    client_conf.write_text(f"""organization: testorg
common_name: client
port: 14000
endpoints:
  - serial_number: "2"
    address_family: ip4
private_key: {args.repo / "integration/org-key.pem"}
registry: {registry}
originate: ["fd00:88::2/128"]
tun: ranet0
child_rekey_interval: 0
ike_rekey_interval: 0
peers:
  - common_name: server
    serial_number: "1"
babel:
  hello_interval: 500ms
  update_interval: 1s
""")
    client_command = [
        str(args.client),
        "-config",
        client_conf,
        "-pprof",
        client_pprof,
    ]
    client_command += ["-metrics", client_metrics]
    if args.affinity:
        client_command = ["taskset", "-c", args.affinity] + client_command
    start(client_command, "client", env=dict(os.environ, GOMAXPROCS=str(args.cores)))
    wait_for(
        lambda: run(["ip", "link", "show", "ranet0"], check=False).returncode == 0,
        "client did not create TUN",
    )
    run(["ip", "addr", "add", "fd00:88::2/128", "dev", "ranet0", "nodad"])
    run(["ip", "route", "add", "fd00:99::/64", "dev", "ranet0"])
    if ranet_peer:
        # Each instance reports its own IKE and babel state, so a half-open
        # mesh fails here naming the side that never came up rather than as a
        # ping that times out for no stated reason.
        live = {}

        def established():
            for name, _, metrics in instances:
                try:
                    text = scrape(metrics)
                except OSError:
                    return False
                live[name] = {
                    metric: sample(text, metric)
                    for metric in [
                        "ranet_lite_sessions",
                        "ranet_lite_babel_neighbor_up",
                    ]
                }
            return all(
                all(value is not None and value >= 1 for value in state.values())
                for state in live.values()
            )

        try:
            wait_for(established, "IKE and babel did not converge", timeout=30)
        except RuntimeError as error:
            raise RuntimeError(f"{error}: {json.dumps(live)}") from error
    wait_for(
        lambda: (
            run(["ping", "-c", "1", "-W", "1", "fd00:99::1"], check=False).returncode
            == 0
        ),
        "ESP/Babel did not converge",
        timeout=30,
    )
    # The baseline the end-of-run check subtracts from. Taken for both arms,
    # since the client exports metrics either way.
    converged = {}
    for name, _, metrics in instances:
        converged[name] = scrape(metrics)
        (args.output / ("converged" + suffix(name) + "-metrics.txt")).write_text(
            converged[name]
        )
        print(
            json.dumps({"instance": name} | babel_state(converged[name])),
            flush=True,
        )
    if not ranet_peer:
        print(
            run(
                ["swanctl", "--list-sas", "--uri", "unix:///run/charon.vici"],
                gateway=True,
                env=env,
            ).stdout,
            flush=True,
        )
    traffic("plain-bidir", "10.200.0.2", ["--bidir"])
    for direction in args.directions.split(","):
        flags = {"bidir": ["--bidir"], "outbound": [], "inbound": ["--reverse"]}[
            direction
        ]
        traffic(direction, "fd00:99::1", flags, collect_profile=True)
    if not ranet_peer:
        xfrm_stat = run(["cat", "/proc/net/xfrm_stat"], gateway=True, check=False).stdout
        (args.output / "xfrm-state.txt").write_text(
            run(["ip", "-s", "xfrm", "state", "list", "nokeys"], gateway=True).stdout
        )
        (args.output / "xfrm-stat.txt").write_text(xfrm_stat)
        # The gateway's own error counters, collected since this harness was
        # written and never read. A run the peer spent discarding replays is
        # not a measurement of this dataplane, and it looks exactly like a slow
        # one.
        discarded = {}
        for line in xfrm_stat.splitlines():
            fields = line.split()
            if len(fields) == 2 and fields[0].startswith("XfrmIn") and int(fields[1]):
                discarded[fields[0]] = int(fields[1])
        if discarded:
            raise RuntimeError(f"the gateway discarded inbound ESP: {discarded}")
    else:
        (args.output / "peer-links.txt").write_text(
            run(["ip", "-s", "link"], gateway=True).stdout
        )
    # Both arms, not only the two-instance one. The client exports metrics
    # either way, and a strongSwan run that ended with no session or with ESP
    # drops is exactly as unusable as a ranet-lite one.
    for name, _, metrics in instances:
        final = scrape(metrics)
        (args.output / ("final" + suffix(name) + "-metrics.txt")).write_text(final)
        report = {"instance": name} | babel_state(final)
        for counter in ["esp_inbound_packets", "esp_inbound_dropped"]:
            metric = "ranet_lite_" + counter + "_total"
            report[counter] = sample(final, metric) - sample(converged[name], metric)
        print(json.dumps(report), flush=True)
        # Each instance decrypts what the other sent, so a direction whose
        # Child SA quietly failed shows up as one side delivering nothing
        # rather than only as a smaller number.
        if (
            report["sessions"] != 1
            or report["neighbors"] != 1
            or report["esp_inbound_packets"] <= 0
            or report["esp_inbound_dropped"]
        ):
            raise RuntimeError(f"degraded run: {json.dumps(report)}")
finally:
    for proc in reversed(processes):
        if proc.poll() is None:
            proc.terminate()
    for proc in reversed(processes):
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait()
