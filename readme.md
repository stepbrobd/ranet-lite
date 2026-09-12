# ranet-lite

Binary Cache:

- Cache: <https://cache.ysun.co>
- Key: `cache.ysun.co-1:WxPYwT5g3kt9XhUhHPpNLZKI9HIOsVVAuqSHpok8Qt4=`

A slim client for a [ranet](https://github.com/NickCao/ranet) mesh: a minimal
IKEv2 initiator, userspace ESP, a real Linux TUN device, and an embedded Babel
routing speaker, all in a single Go binary.

It reads the exact same `registry.json` and Ed25519 key files as `ranet` itself,
so it can join an existing deployment without re-provisioning anything, but it
has its own local config format (see [Configuration](#configuration)) suited to
dialing out to one or a few existing mesh nodes rather than participating in
ranet's full N-to-N reconciliation.

## How it works

- **IKEv2** ([RFC 7815](https://www.rfc-editor.org/rfc/rfc7815)-style minimal
  initiator) using modern cryptography only: X25519, AES-GCM /
  ChaCha20-Poly1305, SHA-256/384. Authenticates with a raw Ed25519 key via
  [RFC 7427](https://www.rfc-editor.org/rfc/rfc7427) Digital Signature auth
  ([RFC 8420](https://www.rfc-editor.org/rfc/rfc8420) EdDSA), and forces UDP
  encapsulation unconditionally on the one explicit registry port, interoperates
  with a real strongSwan responder as provisioned by ranet.
- **ESP** ([RFC 4303](https://www.rfc-editor.org/rfc/rfc4303)) tunnel-mode AEAD
  encap and decap with anti-replay, entirely in userspace, with no kernel XFRM
  state.
- A real **TUN device**, so local applications talk to the mesh over ordinary IP
  sockets through the kernel's own TCP/IP stack, with no SOCKS5 proxy and no
  userspace network stack. Creating the device needs `CAP_NET_ADMIN`. Address
  and route configuration also require administrative privileges and are managed
  separately (see [Configuration](#configuration)).
- An embedded minimal **Babel** speaker
  ([RFC 8966](https://www.rfc-editor.org/rfc/rfc8966)), including the RTT
  extension ([RFC 9616](https://www.rfc-editor.org/rfc/rfc9616)) and IPv4
  announcements with an IPv6 next hop
  ([RFC 9229](https://www.rfc-editor.org/rfc/rfc9229)). Interoperates with
  [BIRD](https://bird.network.cz/) as the reference peer implementation.

## What it deliberately doesn't do

**ranet-lite carries transit in this fork.** Upstream is an RFC 8966 Appendix E
stub that never re-advertises a learned route, which is what made it loop-free
by construction. The speaker here implements the source table and the
feasibility condition instead, and redistributes its selected routes, so loop
freedom comes from the mechanism the RFC provides rather than from an inability
to relay. A node that advertises transit still has to be able to forward it,
which is three things this binary does not do for you: `net.ipv4.ip_forward` and
`net.ipv6.conf.all.forwarding` have to be on, the learned routes have to reach a
kernel table the node actually consults, which is what the `kernel` block below
is for, and the TUN has to be allowed to forward back out of itself. Advertising
transit without them means announced paths blackhole.

It implements genuine source-specific routing
([SADR, RFC 9079](https://www.rfc-editor.org/rfc/rfc9079)): the mesh's route
table is keyed by `(source, destination)` prefix pairs, resolved per RFC
8966/SADR's rule (longest destination match first, source prefix as a tiebreaker
among equally-specific destinations) using each packet's real source address as
it arrives on the TUN device, not an approximation based on a single configured
"our address".

**ranet-lite does not manage the TUN device's address or routes unless you ask
it to.** It creates the device and brings it up, or attaches to the configured
`tun` device, and by default assigning its addresses and kernel routes is
external. This fork adds an optional reconciler, `internal/kernel`, which
mirrors the learned routes into one routing table it owns, or into
interface-scoped routes on darwin, and can assign the configured addresses. See
the `kernel` block in the configuration below. It is off unless enabled.

Babel only exchanges control packets inside authenticated ESP tunnels; a local
routing daemon cannot peer with the embedded speaker over the TUN. Learned
routes select the outgoing ESP peer after the kernel has routed a packet to the
TUN.

IPv4 announcements use the control link's IPv6 link-local next hop (AE 4). The
BIRD peer needs Babel's `extended next hop` support, enabled by default in
BIRD 3. Both ordinary IPv4 updates and AE 4 updates are accepted on receive.

On Linux, ranet-lite opens one multiqueue TUN lane per Go execution context and
keeps inner flows on a stable lane. When more than one execution context is
available, an existing named TUN must therefore be created with
`IFF_MULTI_QUEUE` (for a systemd-networkd `.netdev`, set `MultiQueue=yes` in its
`[Tun]` section). Single-core processes can also attach to a legacy single-queue
TUN. TUN readers hand bounded batches to shared encryption workers; sequence
reservation and queue submission preserve packet order across workers.

The Babel control state and forwarding publication share one mutex. Selection
runs over feasible routes only, against the source table this fork added, since
a speaker that re-advertises what it learns can no longer rely on the structural
loop freedom of
[RFC 8966 Appendix E](https://www.rfc-editor.org/rfc/rfc8966.html#appendix-E).
Every finite advertisement leaves through one function, which records the
feasibility distance before the packet is built. Local prefixes take precedence
even after a router-ID change. Remote Hello, IHU, and Update expiration is
scheduled independently of local send intervals.

Packet lookups read an immutable SADR trie snapshot without locking. Route
changes copy the affected path and publish it atomically; diagnostics iterate
the same snapshot. ESP batches similarly capture an immutable set of installed
SAs, retaining keys for work already in flight during a rekey. One-core receive
processing runs inline; multicore receive workers authenticate concurrently and
commit replay state in intake order before delivering TUN batches. Linux UDP
receive reads a full 128-message vector and returns excess GRO segments before
reusing its buffers. Replay checks and nonce storage are amortized across ESP
batches, and already-completed send/receive batches are combined without waiting
for additional traffic. Encryption workers reuse packed ciphertext buffers only
after the ordered sender finishes its UDP call, retaining separate storage for
work in flight. Replaced inbound SAs remain usable for five seconds after their
Delete acknowledgment so queued and reordered packets can drain during a rekey.

## Deliberate protocol deviations

ranet-lite uses a private IKEv2 transport profile tailored to a ranet deployment
rather than general-purpose
[RFC 7296 NAT traversal](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.23).
The RFC uses UDP ports 500 and 4500, hashes the actual source and destination
address/port pairs in the `NAT_DETECTION_*_IP` notifications, and moves
subsequent traffic to port 4500 when NAT is detected. In contrast:

- Each ranet node listens on its registry-assigned UDP port. The local and
  remote ports are independent and need not have the same value; NAT may rewrite
  either one again.
- IKE and ESP always share that one UDP path. Every IKE packet, including
  `IKE_SA_INIT`, has the four-byte Non-ESP Marker, while an ESP packet starts
  directly with its nonzero SPI.
- The initiator deliberately hashes a random IPv4 address and port zero in
  `NAT_DETECTION_SOURCE_IP`, guaranteeing a mismatch so that strongSwan installs
  UDP encapsulation even when no NAT is present. The destination notification
  hashes the configured remote endpoint normally.
- Received NAT-detection notifications are not used to select a transport: there
  is no port-500-to-4500 transition and no dedicated
  [RFC 3948](https://www.rfc-editor.org/rfc/rfc3948.html) NAT keepalive. The
  userspace transport accepts UDP-encapsulated ESP only, not raw IP ESP.

The strongSwan peer must therefore be provisioned for the same custom port and
forced UDP encapsulation (`encap = true`). This profile remains usable when a
NAT changes the observed source port: replies follow the observed source, and a
fresh authenticated IKE request can update the stored peer endpoint. It is
deliberately not interoperable with an otherwise generic peer expecting standard
RFC 7296 port selection or raw ESP.

There is one separate SHOULD-level deviation from
[RFC 7296 section 2.25.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.25.1).
If both peers initiate a rekey of the same Child SA concurrently, ranet-lite
answers the peer's rekey with `TEMPORARY_FAILURE`. The RFC recommends completing
both exchanges, temporarily retaining the redundant SAs, and using the four
nonces to decide which new SA to delete. Returning the error keeps ranet-lite's
single-Child-SA state machine simple. Both ends fail at the same instant and
reset the same backoff, so the retry is drawn from the upper half of its window
rather than run at the window's end; without that spread the retry reproduces
the phase difference that caused the collision and collides again indefinitely,
which is the jitter
[RFC 7296 section 2.8](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8)
asks for.

The remaining narrow feature set is not counted as RFC non-compliance.
Raw-public-key authentication without certificates or EAP and refusal to create
additional Child SAs are both within the
[RFC 7815 minimal-initiator profile](https://www.rfc-editor.org/rfc/rfc7815.html).

This fork adds the responder role, which upstream lists as out of scope, because
a full mesh needs every node to answer as well as dial. It is off unless
`responder` is set. Identities are compared by name rather than by their DER
bytes: ranet writes `O` and `CN` as `UTF8String` while strongSwan picks the
string type from the value, so one name legitimately reaches the wire in two
encodings. AUTH signs the bytes as received either way, so the name is only what
selects which key must verify it.

IKE rekeys retain the negotiated PRF. This avoids differing key expansion
behavior between
[strongSwan](https://github.com/strongswan/strongswan/blob/master/src/libcharon/sa/ikev2/keymat_v2.c)
and
[RFC 7296 section 2.18](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.18)
when the PRF changes, while allowing fresh DH keys and a different encryption
algorithm. Peer Child-SA rekeys can use X25519, P-256, or P-384 for PFS; locally
initiated Child rekeys derive keys from the IKE SA without an additional DH
exchange.

## Building

```sh
go build -o ranet-lite ./cmd/ranet-lite
```

Requires Go 1.26+. Creating the TUN device needs `CAP_NET_ADMIN` (root, or that
capability granted to the binary).

## Running

```sh
sudo ./ranet-lite -config /etc/ranet-lite/config.yaml
```

On startup it logs the TUN device's name (e.g. `ranet0`). Traffic won't flow
until you configure it yourself, e.g.:

```sh
ip addr add 10.66.0.5/32 dev ranet0
ip route add 10.66.0.0/16 dev ranet0
```

## Configuration

ranet-lite needs two files:

- A **registry.json**, in the exact format ranet itself uses (see
  `internal/registry/testdata/registry.json` for a fully worked, synthetic
  example spanning multiple organizations, nodes, and endpoint address
  families).
- A **config.yaml** in ranet-lite's own format, see
  [`examples/config.yaml`](examples/config.yaml):

```yaml
organization: example
common_name: my-laptop
port: 13000
endpoints:
  - serial_number: "0"
    address_family: ip4

private_key: /etc/ranet-lite/key.pem # PKCS8 PEM Ed25519 private key
registry: /etc/ranet-lite/registry.json # same registry.json ranet itself uses

# Prefixes this node announces via babel as reachable through itself.
originate:
  - "10.66.0.5/32"

# Optional anti-replay window. Omit for the high-speed default of 4096
# packets; RFC 4303 section 3.4.3 recommends increasing it for high-speed
# environments. Set it to 0 only to explicitly disable replay checking.
# replay_window: 4096

# Proactive rekey intervals default to 1h for Child SAs and 3h for IKE SAs.
# Set either to 0 to disable it. Rekeys run interval minus the 5m margin and
# an independently random 0-1m jitter. Margin plus jitter must be shorter
# than every enabled interval.
# child_rekey_interval: 1h
# ike_rekey_interval: 3h
# rekey_margin: 5m
# rekey_jitter: 1m
# Failed rekeys retry after 5s, doubling up to 5m.
# rekey_retry_initial: 5s
# rekey_retry_max: 5m

# The existing strongSwan netns test rig can exercise short rekey lifetimes:
# go run ./cmd/iketest -child-rekey=5s -ike-rekey=15s -run=45

# Optional fixed TUN name. It attaches to an existing compatible device
# (which must be multiqueue on multicore) or creates it when absent. Omit to
# create an automatically named ranet%d device on Linux, or the next free
# utun on darwin, whose control accepts only "utun" or "utunN".
# tun: ranet0

# Answer peers that dial us, rather than only dialing. Off by default: a leaf
# has no address to be dialed at, and an open responder is the one surface an
# unauthenticated peer can reach. Any node in the registry may then dial us;
# the peers list below says who we dial, not who we answer.
# responder: true

# One or more existing mesh nodes to dial as IKEv2/babel peers. Not required
# when responder is set.
peers:
  - organization: example # optional, defaults to the top-level organization
    common_name: gateway
    serial_number: "0" # optional, picks a specific endpoint if the node has several

babel:
  hello_interval: 4s
  update_interval: 16s

# Optional: mirror the routes babel learns into a routing table of its own, taking
# over from BIRD's kernel protocols. Off unless enabled. The reconciler deletes
# only routes carrying its own protocol, in its own table, out of the TUN, and
# an install refuses a key another writer already holds rather than taking it
# over. Give it a table no other daemon writes, or the routes it refuses are
# routes the mesh wanted.
# kernel:
#   enabled: true
#   table: 200                     # the table the policy rules look up
#   protocol: 155                  # rt_proto marking this reconciler's routes
#   metric: 32
#   prefsrc4: 10.66.0.5            # RTA_PREFSRC on v4 routes, as krt_prefsrc does
#   addresses: ["10.66.0.5/32"]    # assigned to the TUN, removed again at exit
#   assign_originated: false       # also assign every prefix in originate
#   vrf: gravity                   # joined only while the link has no master
#   reconcile_interval: 30s
```

Required fields: `organization`, `common_name`, `port`, at least one local
`endpoints` entry, `private_key`, `registry`, and, unless `responder` is set, at
least one entry in `peers`. Everything else has a default
(`peers[].organization` defaults to the top-level `organization`, and the babel
intervals default to 4s/16s).

**Your `registry.json` and private key are sensitive.** They identify and
authenticate a real node in a real mesh. Never commit real copies of either;
only synthetic fixtures belong in version control (see `.gitignore`).

## Metrics

`-metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on its
own listener, separate from `-pprof` so a fleet node can be scraped without
exposing a profiler. It reports what `prometheus-bird-exporter` reported while
Babel lived in BIRD: neighbor liveness and link cost, routes received per
neighbor, routes selected and originated, established sessions per path, and
inbound ESP packet and drop counters. Everything is read from live state at
scrape time, so a scrape reflects the instant it happened rather than a sampled
snapshot.

## Sharing a host with other networking

ranet-lite is built to run next to Tailscale, NetBird, ZeroTier, an SD-WAN
agent, or anything else that owns interfaces and routes on the same box, and the
reconciler's ownership rules are what make that true rather than a hope.

On Linux it reads back only routes whose table, `rt_proto` and output interface
all match its own, so a delete list can never contain another writer's route,
and `RTM_DELROUTE` carries `rtm_protocol` as well, so the kernel refuses too. It
never touches another table, another device, or any policy rule.

Installing is where a router daemon usually takes over from its neighbors, and
this one does not. It asks for the route exclusively, and a key something else
already holds is left alone and reported once. That matters most in a VRF table,
which is what a gravity node hands it: a replace compares neither the protocol
nor the route type, so it would have displaced the kernel's own local and
connected entries for an address on an enslaved link, at the same priority an
IPv4 route with no configured metric uses. The reconciler also names any other
routing protocol it finds in the table at startup.

On darwin there are no tables and no `rt_proto`, so ownership is by interface
and by shape: a route out of its own utun whose gateway is a link address naming
that interface. That condition is the whole guarantee, so it is worth stating
plainly: nothing else writes routes out of our utun. Tailscale's `100.64.0.0/10`
on its own utun has exactly the shape described above, so a reconciler pointed
at that interface would adopt and withdraw it. Two things keep that from
happening. The device is created by asking for the next free unit, so it is
never one another tunnel is already using, and XNU allocates interface indices
by incrementing a counter with no free list, so a destroyed utun's index is
never handed out again.

Interface-scoped routes are narrower still, because a scoped route is what this
reconciler installs for a source-specific announcement and also what other tools
install. A macOS host running Tailscale carries a scoped `255.255.255.255` entry
with a link gateway and `RTF_STATIC`, so a scoped route counts as this
reconciler's only when this process scoped that destination. One left behind by
a crash is left alone rather than deleted on a guess.

Two kinds of route are scoped, for two different reasons. A source-specific
announcement is scoped because interface scope is the only thing on this
platform that draws the distinction a source prefix draws at all. An announced
default is scoped because it would otherwise capture the machine: darwin has one
FIB and no equivalent of the fleet's table plus policy rule, so nothing keeps
the peers' own endpoints out of it and the ESP underlay would route into the
tunnel carrying it. Anything more specific is installed unscoped, so the mesh is
reachable from the Mac without every program binding first. Tailscale makes the
same split on the same machine: its exit-node default is scoped to its utun, its
`100.64.0.0/10` is not.

What a scoped route does not give you is automatic use of an exit-announced
address. Invisibility to an ordinary lookup is the safety property, and it
applies to every unbound socket, so Safari, curl and ssh keep the address of
whatever interface the machine was already using. macOS has no `ip rule`:
selecting a scoped route means `bind()` to an address on the tun or
`IP_BOUND_IF` to the tun itself, per application, and ranet-lite provides
neither. There is a second-order effect worth knowing about too. Once the
outgoing interface has no address of a family, which happens on an IPv4-only
network where the mesh address is the box's only global IPv6, RFC 6724 rule 5
makes the mesh address a candidate source for traffic that is not going through
the mesh at all, and those packets die at the first BCP 38 filter with nothing
to show for it locally.

An install that collides with a route another program holds is reported rather
than retried in silence, since darwin has no replace and the collision does not
resolve itself.

Addresses are narrower still: only an address this process added is ever
removed, and one already on the link belongs to whoever put it there. The TUN is
enslaved to a VRF only while it has no master at all, so systemd-networkd keeps
whatever it already claimed. The device itself is created by asking for the next
free unit, so it never takes a name another tunnel is using.

## Reloading

`SIGHUP` re-reads the config file and the registry and reconciles rather than
restarting. It applies the registry itself, the peers dialed, and the prefixes
originated, so a node joining or leaving the mesh costs one dialer instead of
dropping every SA this node is carrying. ranet's own `ExecReload` works the same
way, and it matters because the registry is rewritten every time any node joins.

Everything else is refused rather than applied, because a reload cannot reach
it. Identity, port, TUN device and local endpoints each change what peers have
already authenticated or what the dataplane is attached to. The `babel` block is
built into the speaker once, apart from the prefixes it originates, which a
reload does apply. The `kernel` block, including the addresses
`assign_originated` expands into, is read once at startup. The rekey and replay
settings are captured by a session when it is created, so applying them to new
sessions alone would leave the node running two policies at once. And
`responder` decides whether the node answers at all, which is wired up before
the reload path exists. A restart is the honest way to change any of them, and a
reload that fails validation changes nothing.

## Repository layout

- `internal/ike` is the IKEv2 initiator and responder.
- `internal/client` owns the runtime, peer reconnection, and the ESP pipeline.
- `esp` is userspace ESP AEAD encap and decap with anti-replay.
- `internal/transport` is the shared UDP socket mux, separating IKE from ESP
  framing.
- `internal/netstack` owns the TUN device and the `(source, destination)` route
  table.
- `internal/babel` is the embedded Babel speaker.
- `internal/kernel` is the optional reconciler. It mirrors learned routes into a
  routing table it owns on linux, or into interface-scoped routes on darwin, and
  assigns the TUN's addresses.
- `internal/packet` validates TUN and decrypted IP packets.
- `sadr` is the immutable source and destination routing trie, with snapshot
  iteration.
- `internal/registry` reads a ranet-compatible `registry.json` and Ed25519 key
  loading.
- `internal/config` is ranet-lite's own config format.
- `cmd/ranet-lite` is the production binary.
- `cmd/*test` are standalone interop and smoke-test binaries used during
  development (IKE, ESP, babel tests).

## Testing

```sh
go test ./... -race
```

None of the unit tests require root or any privileged resource. Protocol-level
interoperability is covered by the NixOS VM test exposed by `flake.nix`. It
boots separate client and gateway VMs; the client runs the packaged, user-facing
`ranet-lite` binary with a real TUN device, while the gateway runs
`charon-systemd`/`swanctl`, BIRD, and iperf3. The test verifies an
Ed25519-authenticated IKEv2 and Child SA negotiation across asymmetric local and
remote UDP ports, checks Babel route exchange in both directions, and measures
TCP bandwidth through the negotiated ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration -L
nix build .#checks.x86_64-linux.integration-multicore -L
```

These checks exercise one-core and four-core clients, IPv4 and IPv6 routes,
locally scheduled and peer-initiated rekeys, BIRD withdrawal/recovery, and a
clean stop/restart with an idle TUN read. The integration test also accepts
`profile = true` when imported from Nix to capture Go and kernel CPU profiles
during longer throughput runs, including simultaneous traffic in both
directions:

```sh
nix build .#integration-profile --no-link -L
```

The kernel profiler runs as root inside the disposable VM. It does not require
host root or changes to the host's profiling permissions. Profiles are copied
into the test result.

`nix build .#namespace-profile --no-link -L` runs the namespace harness below
inside one six-core VM and captures a system-wide kernel profile. This keeps the
veth topology used by host measurements and avoids the virtual switch between
integration-test VMs; the guest's CPU and clock still affect results.

For measurements without VM overhead, use the namespace harness:

```sh
nix develop -c go build -o /tmp/ranet-bench ./cmd/ranet-lite
nix develop -c unshare --user --map-root-user --mount --net \
  python3 integration/performance.py --client /tmp/ranet-bench \
  --output /tmp/ranet-perf-6 --cores 6 --affinity 0-5 \
  --directions outbound,inbound,bidir
```

Run as an ordinary user with unprivileged user namespaces available. The harness
creates private client/gateway network namespaces, a private `/run`, strongSwan,
BIRD, and a real TUN/XFRM tunnel using the synthetic test keys. It records
binary identity, CPU affinity, iperf3 JSON, CPU profiles, socket drops, and
key-free XFRM counters in a new output directory. All processes and interfaces
are removed when the namespaces exit.

`--cores` sets GOMAXPROCS; `--affinity` restricts the client to actual CPUs. Use
`--cores 1 --affinity 0` for a pinned single-core comparison. Keep flow ports,
stream counts, affinity, MTU, and replay windows identical between versions. The
default gateway replay window is strongSwan's 32 packets; `--replay-window 4096`
can distinguish replay drops from processing limits. `--protocol udp --rate 10`
offers an aggregate 10 Gbit/s per direction with UDP GSO/GRO and 4 MiB iperf
socket buffers; inspect received throughput and loss, not just the offered rate.
The Nix development shell uses the `iperf3-benchmark` package, which changes
[iperf 3.21's GRO receive call](https://github.com/esnet/iperf/blob/3.21/src/net.c#L521-L595)
to block instead of busy-polling. With the upstream receive loop, eight
bidirectional streams can occupy every CPU even when waiting for packets,
starving the tunnel on a shared host. The harness records the exact iperf
executable and version along with the client binary identity. TCP behavior is
unchanged.

Raw ESP encryption and decryption have separate benchmarks:

```sh
nix develop -c go test ./esp -run '^$' -bench 'BenchmarkESP' \
  -benchmem -cpu=1,2,4,8 -count=5
```

These include ESP framing, AEAD, sequence reservation or replay commits, and
reusable batch buffers. Decryption also includes copying the input ciphertext
into reusable buffers. They exclude UDP, TUN, and the client queues; cipher
throughput cannot establish full-duplex tunnel throughput. Namespace
measurements share CPU resources with the Linux gateway and traffic generators
and do not establish performance on a physical NIC.

To compare routing and packet classification across CPU counts:

```sh
go test ./sadr ./internal/babel -run '^$' \
  -bench 'BenchmarkLookup|BenchmarkRouteChange|BenchmarkReceiveData' \
  -benchmem -cpu=1,2,4,8 -count=5
```

Compare runs on the same idle host. Lookup throughput, route-update cost, and
full-tunnel TCP bandwidth measure different work; VM throughput also includes
the gateway's kernel IPsec and virtual networking overhead.

Immutable snapshots favor packet lookups over route-write latency. Each changed
route allocates the copied trie path; this costs more than an in-place update,
but readers never contend with other readers or wait for a route writer.

The VM console, systemd, strongSwan, BIRD, ranet-lite, and iperf3 output is
streamed by the Nix test driver. The test also prints strongSwan SA state and
BIRD neighbors and routes on exit, including after a failed check.

## License

MIT, see [license.txt](license.txt).
