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
stub that never re-advertises a learned route, which made it loop-free by
construction. The speaker here implements the source table and the feasibility
condition instead, and redistributes its selected routes, so loop freedom comes
from the mechanism the RFC provides rather than from an inability to relay. A
node that advertises transit still has to be able to forward it, which is three
things this binary does not do for you: `net.ipv4.ip_forward` and
`net.ipv6.conf.all.forwarding` have to be on, the learned routes have to reach a
kernel table the node actually consults, which `cap.table` below is for, and the
TUN has to be allowed to forward back out of itself. Advertising transit without
them means announced paths blackhole. `cap.egress` below acts on the same fact
rather than warning about it: a prefix an exit node offers to carry is
advertised only while its translation rule is installed and the kernel forwards
its family, and is retracted the moment either stops being true.

`dial.all` dials every node the trust document names, the N-to-N reconciliation
ranet performs. Entries in `dial.to` still apply and win for their node, which
is the only way to pin a `serial`. Reach against a fleet running BIRD requires
it, because that Babel channel exports only its own directly connected routes: a
node learns a prefix from the node that originates it or not at all, so dialing
a few exits reaches those exits and nothing behind them.

A node that takes an exit-announced default should set `link.underlay`. It is
one block covering both platforms because it is one idea: keep the one UDP
socket carrying IKE and ESP out of the reach of the routes the mesh installs.
The transport binds the wildcard and lets the kernel pick the source by route,
so on a node whose mesh address is the only global address of its family the
kernel picks that address, a `from <mesh address>` policy rule sends the
datagram to the mesh table, and an exit-announced default there routes the ESP
underlay into the tun carrying it.

`link.underlay.mark` is `SO_MARK`, linux only, and the reconciler installs the
rule matching it: write it under `cap.table.rules`, as
`{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }`. The two
halves are one setting written in two blocks, so a node that writes `cap.table`
and leaves that rule out is refused by name: a marked socket no rule selects on
follows the mesh table exactly as an unmarked one would. A node configuring its
routes elsewhere writes no `cap.table`, and the rule goes wherever those routes
do.

`link.underlay.bind` is `IP_BOUND_IF` and `IPV6_BOUND_IF`, darwin only, set to
the interface the host's own default route leaves by and moved with `setsockopt`
on the live descriptor when that changes, so a laptop crossing from wifi to a
dock keeps every SA. It scopes that socket's route lookups to that interface,
which is the only thing on that platform that can make a real default out of the
tun safe, so the same setting tells the reconciler to install an announced
default plain rather than interface-scoped. Leaving it off keeps the scoping
described under the platform notes below: reachable, and reachable by nothing
that did not name the tun, so the node can hold an exit-announced address and
cannot send its traffic through the exit.

Binding is necessary and, on macOS 26, not sufficient on its own, which
`TestDarwinBoundSocketNeedsAScopedDefault` measures. `IP_BOUND_IF` does not take
a socket out of the forwarding table: the scoped lookup still finds the most
specific route, and where that route leaves another interface it falls back only
to a route already on the bound one. So while the mesh holds `0.0.0.0/1` and
`128.0.0.0/1` out of the tun, a bound socket answers `ENETUNREACH` unless the
underlay's own interface carries a default scoped to it, the route
`route -n add -net 0.0.0.0/0 <next hop> -ifscope <interface>` writes. macOS
writes exactly that for every interface but the primary one, which is why
binding looks sufficient right up until the mesh takes the default away from the
primary.

ranet-lite writes it, and it is the only route this tree puts out of an
interface it does not own, so the rules around it are narrower than the tun's.

It is written whenever the socket is bound rather than only when the mesh looks
like it is capturing. Writing it under a condition meant every set that slipped
past the condition took the machine off the network with nothing to fall back
on, and three ordinary announcements are such a set. It duplicates the host's
own default on the interface that already carries it, so it costs nothing when
nothing needs it.

The reconciler asks once a pass, and drops from that pass every capturing route
whose own family the underlay cannot fall back on, so such a route is neither
installed nor left behind: the host's default moving to another interface
withdraws one that is already in the kernel. The answer is per family, because
the fallback is: a bound socket resolves the unspecified address of the
destination's own family, so a covered IPv4 does nothing for a `::/0` capture.
That is an invariant rather than a sequence, on both edges.

It is reconciled rather than remembered. The kernel drops this route on its own,
clearing `IFF_UP` purges it and bringing the interface back up does not restore
it, so every pass reads the table back and writes what is missing; a record
saying it was written says nothing about whether it is there. The record is the
claim to delete it and nothing else.

It follows the host's own default: the interface it is going to is written
before the socket moves onto it and the one it left is cleared after that, which
leaves no moment with no usable route. Only a route this tool recorded writing
is ever withdrawn, only after a readback finds it still carrying `RTF_IFSCOPE`,
the recorded interface and the recorded next hop, and a delete that is not
interface-scoped cannot be encoded at all. An add that answers `EEXIST` is
success and not ownership, so a route macOS wrote for a secondary interface is
used and never removed. Nothing is withdrawn while a capture is still in the
kernel, so a withdrawal that failed upstream cannot take the fallback away from
under one.

The record outlives the process. It is written to
`/var/run/ranet-lite/underlay.json`, beside the control socket's lock, before
the route is written and after it is withdrawn, so a daemon killed with
`SIGKILL` is cleaned up by the next one rather than leaking. That is the same
ownership claim made durable, not a weaker one: a restart withdraws a recorded
route only when the kernel still holds one matching its destination, interface
index, next hop and `RTF_IFSCOPE`, only when the recorded interface name still
resolves to the recorded index, and only when that interface also carries the
host's own unscoped default. The last clause separates our route from the
system's, because macOS writes a scoped default for every interface except the
one holding the unscoped default;
`TestNoOtherProgramScopesADefaultToThePrimaryInterface` asserts that on whatever
machine the suite runs on rather than taking it on trust. A record failing any
clause is kept where nothing in the process can delete it, so the clauses are
not undone by the next ordinary withdrawal, and the next start weighs them
again. The file is locked before it is read, so a second daemon starting beside
a running one reclaims nothing and overwrites nothing; a state file that is
missing, truncated or not JSON is reported and treated as empty, because a node
that will not start is worse than a route left behind.

The edge that leaves is worth knowing. The last clause is a snapshot, so a host
that makes another interface primary while our route is in place, and later
makes it primary again, could have a restart withdraw a scoped default macOS
wanted there. That is one route on one interface until the next link event,
which macOS answers by rewriting it.

Either way, a route that would carry this machine's own traffic is held back
until at least one session is live, withdrawn once none has been live for
`cap.table.capture_grace` (10s by default) and restored on the next live
session. Such a route is one covering half a family's address space or more, or
one covering that family's unspecified address however small, which is the
kernel's own trigger rather than a rule of thumb: measured for both families,
`0.0.0.0/24` out of the tun costs a bound socket as much as `0.0.0.0/1` does and
`::/64` costs it as much as `::/1`, while a set with no member larger than a
quarter took this machine off the network. `capture_grace` has a floor of one
second, refused by name below it: the gate is sampled once a pass and a pass
reads the routing table, so a shorter grace only sets how often that happens,
and the wake it asks for is armed only while a capturing route is actually in
play. A session counts as live only while it is still proving its peer is there
and only while the underlay socket is where `link.underlay` says it should be.
Without that rule a laptop whose mesh has gone loses every network it has rather
than only the mesh, and it cannot recover on its own, because reaching the peers
needs the network the default just took.

The capture itself has to be the pair of halves rather than a real default.
darwin has no route replace, so `0.0.0.0/0` out of the tun collides with the
host's own and is refused, while `0.0.0.0/1` with `128.0.0.0/1` wins the lookup
outright. `::/1` with `8000::/1` is the same arrangement for IPv6 and is handled
the same way throughout: the gate, the scoping decision and the scoped default
all read a prefix of length zero or one as carrying this machine's own traffic,
whichever family it is. What announces that pair is the exit, not this node.

A leaf should write `transit = false` under `cap.route`, which advertises only
the prefixes this node announces and never relays one it learned. Redistribution
serves a converted fleet and turns a laptop into a transit router for everybody
else. The BIRD side of a ranet fleet draws the same line with
`export where proto = "dbabel0"`. Refusing to advertise cannot close a loop, so
this only narrows what the feasibility condition already bounds.

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
mirrors the learned routes into one routing table it owns, or on darwin into the
single table that platform has, scoping the ones that would otherwise capture
the machine, and can assign the configured addresses. See the `kernel` block in
the configuration below. It is off unless enabled.

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
rather than run at the window's end. Without that spread the retry reproduces
the phase difference that caused the collision and collides again indefinitely,
which is the jitter
[RFC 7296 section 2.8.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8.1)
asks for.

A responder switches its outbound Child SA to the replacement just before it
sends the rekey response rather than just after.
[RFC 7296 section 2.8.1](https://www.rfc-editor.org/rfc/rfc7296.html#section-2.8.1)
permits sending on the new SA "as soon as it sends its response", so the
difference is the time to encrypt one message. What the same section also offers
is the conservative option, continuing on the old SA until the peer proves it
has the new one, and that would close the gap outright: either way the peer
cannot decrypt until the response reaches it, so a peer-initiated rekey costs
the response's flight time of outbound traffic. Since the end with the shorter
lifetime drives rekeying, on a mixed fleet that is strongSwan, hourly, per peer,
and babel's own traffic is periodic enough not to notice.

The remaining narrow feature set is not counted as RFC non-compliance.
Raw-public-key authentication without certificates or EAP and refusal to create
additional Child SAs are both within the
[RFC 7815 minimal-initiator profile](https://www.rfc-editor.org/rfc/rfc7815.html).

This fork adds the responder role, which upstream lists as out of scope, because
a full mesh needs every node to answer as well as dial. It is off unless
`link.listen` is set. Identities are compared by name rather than by their DER
bytes: ranet writes `O` and `CN` as `UTF8String` while strongSwan picks the
string type from the value, so one name legitimately reaches the wire in two
encodings. AUTH signs the bytes as received either way, so the name only selects
which key must verify it.

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
sudo ./ranet-lite daemon --config /etc/ranet-lite/config.toml
```

On startup it logs the TUN device's name (e.g. `ranet0`). Traffic won't flow
until you configure it yourself, e.g.:

```sh
ip addr add 10.66.0.5/32 dev ranet0
ip route add 10.66.0.0/16 dev ranet0
```

`daemon` is the node; every other subcommand speaks to a running one over its
control socket, so `ranet-lite status` and its siblings work alongside a
deployment's own `ranet-lite daemon` with no second binary and no second unit.
Most of them ask a question; `disable`, `enable`, `redial`, `rekey` and `reload`
act on one. See [Control socket](#control-socket).
`ranet-lite completion
bash|zsh|fish` writes the shell's completion script,
generated from the command tree so a command added without one is completed
anyway, and a peer or a subsystem an argument takes is completed from the
running node.

## Configuration

ranet-lite needs two files:

- A **trust document**, today a `registry.json` in the exact format ranet itself
  uses (see `internal/registry/testdata/registry.json` for a fully worked,
  synthetic example spanning multiple organizations, nodes, and endpoint address
  families).
- A **configuration file**, read by the extension it carries: `.toml` goes to
  the TOML parser, and `.yaml`, `.yml` and `.json` go to the YAML one, since
  valid JSON is valid YAML. An extension neither knows is refused by name rather
  than sniffed. Both decoders are strict, so an unknown key is an error under
  either: a mistyped capability that silently does nothing is the worst failure
  a configuration file has. See [`examples/config.toml`](examples/config.toml)
  for the annotated reference, [`examples/config.yaml`](examples/config.yaml)
  for the same schema in YAML, and
  [`examples/config.json`](examples/config.json) for it in JSON. All three
  describe one node, which a test holds by loading each and comparing the three
  whole. JSON carries no comment and the decoder refuses an unknown key, so that
  example cannot annotate itself and cannot smuggle an explanation in under a
  spare key either; it is the form a generator or a control plane writes, and
  the TOML file is where the keys are explained.

The top level says what the node **is**. Everything it **does** lives under
`cap`, one block per capability, and writing the block turns that capability on.
There is no `enabled` field to forget. A default deployment writes `node`,
`auth`, `link` and `dial` and stops:

```toml
[node]
org = "example"
name = "my-laptop"

[auth]
key = "/etc/ranet-lite/key.pem"     # this node's own PKCS8 PEM Ed25519 key
trust = "/etc/ranet-lite/trust.json" # the document saying who may join

[link]
port = 13000
endpoints = [{ serial = "0", family = "ip4" }]
# listen = true                     # answer peers that dial this node
# tun = "ranet0"                    # attach to this device rather than a new one
# [link.underlay]                   # keep the underlay out of the mesh's own routing
# mark = 0x726c                     # SO_MARK plus a rule under cap.table.rules, linux only
# bind = true                       # IP_BOUND_IF plus a scoped default, darwin only

[dial]
# all = true                        # dial every node the trust document names
to = [{ name = "gateway", serial = "0" }]

[cap.route]
announce = ["10.66.0.5/32", { prefix = "::/0", from = "2001:db8:1::/48" }]
# transit = false                   # stop relaying what this node learns
```

Required: `node.org`, `node.name`, `auth.key`, `auth.trust`, `link.port`, at
least one `link.endpoints` entry, and, unless `link.listen` or `dial.all` is
set, at least one `dial.to` entry. Everything else has a default, and an absent
capability is its own default: a node with no `cap.babel` runs the 4s and 16s
intervals of RFC 8966 Appendix B, and a node with no `cap.route` announces
nothing and still carries transit.

The capabilities, each documented in full in the example:

| block         | what it turns on                                                             |
| ------------- | ---------------------------------------------------------------------------- |
| `cap.route`   | what this node announces, and whether it relays what it learns               |
| `cap.babel`   | the speaker's own timers, link quality estimator and costs                   |
| `cap.table`   | the route reconciler: a routing table, addresses, a VRF and policy rules     |
| `cap.segment` | segment routing, RFC 8986: the SIDs this node answers for and what it steers |
| `cap.crypto`  | the replay window and the rekey timers                                       |

A capability is defined once, by the package that implements it, and validates
itself there: `cap.table` is the type `internal/kernel` takes, `cap.segment`'s
members are `srv6`'s, and `internal/babel` takes `cap.babel` and `cap.route`
directly. `internal/config` holds the node's own facts and the checks that span
two capabilities, such as a SID that is also an address the reconciler assigns.
The scalar spellings, a duration, a prefix, an address, a table and an
announcement, live in `schema` and carry both decoders, so a field parses the
same way whichever extension the file has.

**Your trust document and private key are sensitive.** They identify and
authenticate a real node in a real mesh. Never commit real copies of either;
only synthetic fixtures belong in version control (see `.gitignore`).

## Metrics

`-metrics 127.0.0.1:9669` serves `/metrics` in the Prometheus text format on its
own listener, separate from `-pprof` so a fleet node can be scraped without
exposing a profiler. It reports what `prometheus-bird-exporter` reported while
Babel lived in BIRD: neighbor liveness and link cost, routes received per
neighbor, routes selected and originated, established sessions per path, packets
each peer refused to queue, and inbound ESP packet and drop counters.

It also reports the three subsystems that have no exporter anywhere, because on
a fleet node they were the kernel's: the route reconciler, which replaced BIRD's
kernel protocols, as routes installed and skipped, when its last pass finished
and whether that pass failed; segment routing, which replaced `seg6local`, as
what this node did for peers (forwarded, delivered, dropped, answered) and what
it did with its own traffic (steered, and dropped with a reason); and the
`cap.egress`, as rules installed, connections translated, other translation
found at the same hook, and the two prefix counts whose difference says this
node is withholding an advertisement it cannot stand behind. A node with the
reconciler or the capability off writes none of its series rather than zeroes
that read as a subsystem installing nothing.

Everything is read from live state at scrape time, so a scrape reflects the
instant it happened rather than a sampled snapshot. What a counter cannot carry,
the per-neighbor route lists and the route table, is on
[the control socket](#control-socket) instead.

## Segment routing, in this process

The fleet's SRv6 is `ip route ... encap seg6local`, which is a linux facility
and only a linux facility: darwin has no segment routing, and a
`NEPacketTunnelProvider` or a `VpnService` is handed a tun and a list of routes
and never sees a forwarding table. Waiting for each platform's kernel would mean
segment routing on one of the four.

It does not have to be the kernel's, because this process is already the
dataplane. A packet leaving a node is read off the tun here, routed here and
sealed into ESP here, so pushing an outer IPv6 header and a routing header in
front of it is one more step on a path that already copies. A packet arriving is
decrypted here before anything else sees it, so a segment addressed to this node
is acted on before it reaches the tun. `srv6` implements
[RFC 8754](https://www.rfc-editor.org/rfc/rfc8754)'s header and
[RFC 8986](https://www.rfc-editor.org/rfc/rfc8986)'s H.Encaps, End and End.DT46,
and the same code runs on every platform.

`cap.segment.local` names the addresses this node answers for. `End` moves a
packet to its next segment and sends it on; `End.DT46` strips the outer header
and hands what was inside to the stack. The spelling is the one
`ip route ... encap seg6local action` takes, so a fleet's own SIDs move across
unchanged. The AS10779 fleet writes `End` at `<base>6::2` and `End.DT46` at
`<base>6::1`, with `<base>6::3` a second `End.DT46` into the egress VRF.

`cap.segment.steer` is which of this node's own packets go through a segment
list. It is keyed by source and destination prefix together, the pair the
forwarding table is keyed by, because that is the selector a steering tool on
such a fleet uses: the traffic sourced from this node's announced address,
through the waypoints and out at a chosen exit. An entry naming neither a source
nor a destination is refused, since it would claim the encapsulated packets this
node has just produced.

Every steered packet carries its segment list inside the tunnel, so the device
comes up with the longest configured list taken off its MTU, and a list long
enough to take it under the 1280 byte minimum IPv6 requires is refused rather
than installed. Steering happens before the route lookup, because a steered
packet is routed by the segment it is going to rather than by the address it was
addressed to. The outer header takes its traffic class, flow label and hop limit
from the packet it carries, as `__seg6_do_srh_encap` does, so a steered path
costs the packet one hop per waypoint and a packet that arrives with nothing
left to spend is answered with an ICMP Time Exceeded rather than dropped in
silence. A packet a policy claims and this node does not send is dropped rather
than put out by the route the policy exists to override, because a policy here
selects an exit and that route puts the packet out of another node under a
source it does not announce, which is a wrong path rather than a degraded one.
There are two ways to lose one and `status` counts them apart: too large to
encapsulate, which every other reason being refused when the configuration is
read leaves as the only one, and no route to the first segment, which is the
mesh rather than the configuration. Neither is counted against the segments this
node answers for, since neither is anything a peer did.

A header this tree writes is one the kernel acts on, which the `segments` VM
check holds: the client steers through a SID the gateway answers for with
`seg6local`, `tcpdump` parses the header as `RT6 (len=2, type=4, segleft=0)`,
and removing the SID leaves the encapsulated packet arriving with nothing coming
out of it. The other direction, a header the kernel writes and this tree acts
on, is held by the unit tests in `srv6` against a reconstruction of what
`__seg6_do_srh_encap` produces, and by no VM arm: no arm configures
`cap.segment.local`, so `End` and `End.DT46` have no end-to-end coverage.

## Exit nodes and subnet routers

The `cap.egress` block makes this node carry other nodes' traffic out of the
mesh. One action covers both features a customer asks for: an exit node
advertises `0.0.0.0/0` and `::/0`, a subnet router advertises the prefixes
behind it, and each ends at the same operation. A packet arrives on the TUN, its
source is translated to an address the far side can answer, and the host
forwards it by its ordinary routes. linux only for now; the capability is
refused by name where there is no packet filter to write into, because a node
that accepted the configuration and translated nothing would advertise itself
and then drop every flow that took it.

A translating node needs both shapes of policy rule, not only the one selecting
on its own source. Conntrack reverses the translation before the reply is
routed, so the reply is addressed into the mesh and has to meet a rule sending
it to the mesh table. Without that rule the outbound half works and looks right,
the translation counter moves, and every reply leaves by the physical uplink
instead, which presents as an exit that answers nothing rather than as a rule
that is missing. Measured on two nodes on one switch: with the `from` rule alone
the counter reported the flow and the ping lost every packet; adding the `to`
rule made it 4 of 4.

Both interfaces are matched, never one. A packet that arrives on the TUN and
leaves by it again is mesh transit, and rewriting its source would put this
node's address on a packet it is only relaying. A packet this host generated
itself has no arrival interface at all, which recent kernels report as the empty
name rather than as a failure to read, so the inbound direction tests the
interface index against zero as well: without it, this node's own mesh traffic
would go out under the return source, which on an exit is an address belonging
to somebody else.

`source4` and `source6` say what the source becomes. Omitted, or written as
`auto`, the host's own routes decide it per packet, which is the only answer
available to a deployment that owns no address block: on the way out of the mesh
that is the address of the link the packet leaves by, and on the way in it is
this node's own mesh address, which is unique per node and routable within the
mesh. An address written out is used unchanged in both directions, which is how
a deployment with an address block of its own pins the address return traffic
comes back to, and the only way to make a reply land on a chosen node rather
than on whichever one it reaches first.

`return: true` translates the other direction as well, which a subnet router
needs where the mesh holds no route back to the network behind it. An exit node
does not, since nothing sits behind it to start a flow. A node carrying more
than one mesh address of a family is refused rather than picked from, because
the choice decides the address every flow out of its LAN appears as and a guess
would change under an unrelated edit.

**An exit that cannot translate refuses to advertise.** Babel carries no
capability signal: a node that advertises a prefix is promising to carry it, and
the only thing a peer ever learns is the advertisement, so an exit whose rule
will not install would attract traffic and drop it with nothing to tell the
sender. The advertisement is therefore published by the capability rather than
by the configuration, per family and on every pass: a prefix is announced only
while its rule is installed and `net.ipv4.ip_forward` or
`net.ipv6.conf.all.forwarding` is on for its family, and it is retracted the
moment either stops being true. `status` prints what is being announced and what
is being withheld, and the scrape carries both counts. It is the same fact the
transit warning above is about, read from the same place and acted on here
because this end is the only one that knows.

The return path is conntrack's. A reply arriving for a translated flow has its
destination put back before the forwarding lookup runs, so the route to the peer
has to be in a table that lookup consults: with the mesh's routes in a table of
the reconciler's own, that means a `cap.table.rules` entry sending the mesh
prefixes there. Without one the translation works and every reply is dropped.

```toml
[cap.egress]
advertise = ["198.51.100.0/24"] # an exit node writes ["0.0.0.0/0", "::/0"]
# source4 = "auto"                # or an address; auto lets the host's routes decide
# source6 = "auto"
# return = true                   # also translate into the mesh, for a subnet router
# sweep = "30s"
```

## What each platform gives the reconciler

The reconciler's job is the same everywhere and the facilities under it are not,
so the configuration names what it wants and each backend reaches it the way its
kernel allows. A backend that cannot reach something refuses the configuration
by name at startup rather than coming up with a working mesh and no steering,
which is the failure that reads as a routing problem for a day.

**linux** has policy rules and 2^32 tables. `cap.table.rules` are installed with
`FRA_PROTOCOL` set to `cap.table.proto`, the same ownership marker the routes
carry, so a dump reads back only this reconciler's and a delete can never reach
another writer's. systemd-networkd stamps `RTPROT_STATIC` on the rules it
writes, so a node mid-migration keeps the two sets apart on its own.
`cap.table.vrf.create` makes the master device the mesh table is bound to when
no device of that name exists. One this process created is removed again at
shutdown. One it found is left alone with everything in its table, whatever
table that is: a device somebody else bound to another table is adopted as it
stands, so the tun's lookups go there rather than to `cap.table.id`.

**darwin** has one forwarding table, no rules and no VRFs, and refuses
`cap.table.rules`, `cap.table.vrf` and `cap.table.prefsrc4` by name. It reaches
the two ends the rules exist for with interface scope instead: an announced
default and a source-specific route are installed scoped to the tun, so no
unbound socket can select either, which keeps the machine from being captured
and the ESP underlay out of the tunnel carrying it. `link.underlay.mark` is
refused there for the same reason, since there is nothing for a mark to select
and nothing to select it with; `link.underlay.bind` is the local spelling, and
with it set the socket's lookups are scoped to the underlay interface, that
interface is given a default of its own, and an announced default is installed
plain, without which a node cannot use a mesh exit. A source-specific route and
a retracted one stay scoped either way: interface scope is the only thing on
this platform that expresses a source at all, and an unscoped hold at a default
answers the whole machine's traffic with an error.

**iOS and Android**, planned rather than present, have less again: the tunnel is
a `NEPacketTunnelProvider` or a `VpnService`, the process is handed a list of
routes to include and exclude, and there is no table, no rule and no netlink at
all. The underlay stays out of the tunnel because the platform keeps it out,
`VpnService.protect` on one side and the provider's own socket handling on the
other, so a mark is unnecessary there as well. What the reconciler computes, the
set of prefixes the mesh reaches and the source prefix each one is for, maps
onto those lists directly; what it will not have is a table to put them in.

The control surface is platform-neutral by construction. `control` holds the
types and the handler and speaks no transport of its own, so the unix socket is
how linux and darwin reach it and a mobile app reads the same JSON over the
extension's own channel.

## Control socket

`--control /var/run/ranet-lite/control.sock` is where the daemon answers, and is
the default, so a node is askable without having been configured to be.
`--control ""` turns it off. The socket is mode 0660 and the unit names the
group that can reach it, and that mode is the whole authorization story; see
[the verbs](#acting-on-a-running-node) for the line that keeps it sufficient. A
caller is bounded by an idle timeout and by a limit on the connections open at
once across every caller, because a client that accumulates them costs the
daemon a descriptor apiece and a node out of descriptors is one that cannot be
asked anything at all. Past that limit a connection is closed as it is accepted,
so a client holding every place is refused at once rather than left waiting, and
a shutdown is not held up behind it.

Which process owns the path is settled by an exclusive lock on a sibling file
rather than by dialing the socket to see whether anything answers, since a live
daemon out of descriptors and one whose socket the caller cannot open both fail
to answer and neither has stopped owning its path. A socket a dead instance left
behind is cleared under that lock, a path that is not a socket is refused by
name, and a path an operator named and this node cannot bind refuses the
startup. The default path warns and carries on instead, because it is on without
having been asked for.

The version a node reports is `version.txt` and the commit the binary was built
from, because `version.txt` moves once per release and a fleet is converted one
node at a time in between. `ranet-lite version` asks the binary the same
question without a node running, and `ranet-lite version --daemon` asks the
node, which is how the two are told apart during a conversion.

The subcommands read it and print a table, or the wire form with `--json`:

```
$ ranet-lite status
node        example/laptop
version     2026.912.0+860393bf1c2e
uptime      3h12m0s
port        13000
endpoints   0/ip6 1/ip4
tun         ranet0 mtu 1400 queues 16
role        initiator, responder, full mesh, no transit
forwarding  ipv4 on ipv6 on
registry    /etc/ranet/registry.json, 142 nodes in 31 organizations
kernel      table 200 protocol 155, 609 installed, last pass 12 seconds ago
dialers     117 running
sessions    83
neighbors   83, 81 alive
routes      611 prefixes, 604 selected, 3 originated
originate   198.18.104.117/32 3fff:a::198:18:104:117/128 3fff:1:69c:8c0::/60
segments    3fff:1:69c:8c6::1 End.DT46 (0 forwarded, 5 delivered, 0 dropped)
steering    from 3fff:a::198:18:104:117/128 via 3fff:1:69c:98d6::1 (12 steered, 2 with no route to their first segment)
esp         41822931 in, 0 dropped, 14 refused

$ ranet-lite neighbors
peer            state  cost  rxcost  rtt      routes  expires  dropped  failed
example/gateway@0  up     116   96      27.2ms   15      11.3s    0        0
example/relay@1    up     194   96      176.7ms  130     9.8s     0        0

$ ranet-lite routes
destination  from            via             metric  router-id         seqno  paths
::/0         3fff:a::/36  example/gateway@0  212     0a1b2c3d4e5f6071  42     7
```

`neighbors` answers `birdc show babel neighbors`, with the neighbor's own
reported rxcost beside this node's cost so a link that carries one way can be
told from one that carries neither, and with the two dataplane counters BIRD has
no equivalent of. `routes` answers `birdc show route`, over the Babel route
table rather than the forwarding table, so a prefix every neighbor has retracted
is still a row, which is the case an operator is looking for. `sessions` answers
`swanctl --list-sas`. `peers` lists who this node dials, from the config file or
from the trust document under `dial.all`, and whether it got there.

Four more answer questions rather than printing one subsystem. `whois <address>`
is a longest prefix match over that route table: it says which prefix covers an
address and which peer this node reaches it through, then what the address would
fall back to. It names the peer and not the originating node, because Babel
carries a router id and no name and this tree gives each speaker a random one,
so an origin is nameable only where it is a neighbor. `ip` prints this node's
own mesh addresses, one per line, taken from the host prefixes it announces.
`exit-node list` is the defaults the mesh advertises and which of them this node
would take, with a withdrawn one told from one that is carrying traffic.
`bugreport` is every subsystem in one JSON object, and a read that did not
answer leaves its own line in it rather than replacing the report, so a node
that is half up still produces one.

`metrics` prints the same scrape the metrics listener serves, read over the
control socket, so a node's counters are readable without it binding a port a
fleet then has to firewall.

### Acting on a running node

Five subcommands change what a node is doing right now: `disable` and `enable` a
subsystem, which is `reconciler`, `steering` or `responder`; `redial <peer>`;
`rekey <peer>` or `rekey --all`; and `reload`, which does what SIGHUP does so a
supervisor is not the only way to ask.

None of them changes the configuration. A node's configuration is its file, and
that stays its only entry point. What these act on is operational state the file
already decides: `cap.table`, `cap.segment`'s steering, `link.listen`, the peers
list and the file itself. Whoever may edit that file could already ask for every
one of them, by editing and restarting if not by editing and sending SIGHUP, so
the socket's mode grants nothing the file's permissions did not, and a verb that
reached past what the file can express would break that and is refused on those
grounds. The subsystem names are a closed set for the same reason. The two
halves are told apart by method rather than by path: a read answers GET and
nothing else, and a verb answers POST alone.

The state lives in the process. A restart starts everything the file names, and
a reload leaves a stopped subsystem stopped, because the trust document is
rewritten every time any node joins the mesh and a reload that started one again
would undo a decision an operator took minutes earlier on a schedule nobody
chose. A node running less than its file says reports it on the `disabled` line
of `ranet-lite status`, which is the only place that difference shows.

`disable reconciler` withdraws every route, address and rule the reconciler
installed, as `birdc disable` did to a kernel protocol, rather than freezing a
table nobody is maintaining. `disable steering` leaves the policies loaded and
stops acting on them, so a diagnostic still reports what was stopped.
`disable responder` refuses the next handshake and leaves the sessions this node
already holds alone. `redial` is the answer to the finding from the butte
cutover: a peer that dials this node and cannot be dialed back does not retry on
its own, and one of them carried a dead session for sixteen minutes. It drops
what this node holds for that peer and sets its dialers going at once rather
than after the reconnect delay.

This is still not the daemon and client split tailscale has: there is no login
flow here, identity being a static key and a registry entry that nix and sops
put in place before the process starts.

## Sharing a host with other networking

ranet-lite is built to run next to Tailscale, NetBird, ZeroTier, an SD-WAN
agent, or anything else that owns interfaces and routes on the same box, and the
reconciler's ownership rules make that true rather than a hope. `cap.egress`
follows the same rules in the host's packet filter, see below.

On Linux it reads back only routes whose table, `rt_proto` and output interface
all match its own, so a delete list can never contain another writer's route,
and `RTM_DELROUTE` carries `rtm_protocol` as well, so the kernel refuses too. It
never touches another table, another device, or any policy rule.

Installing is where a router daemon usually takes over from its neighbors, and
this one does not. It asks for the route exclusively, and a key something else
already holds is left alone and reported once. That matters most in a VRF table,
which a mesh node hands it: a replace compares neither the protocol nor the
route type, so it would have displaced the kernel's own local and connected
entries for an address on an enslaved link, at the same priority an IPv4 route
with no configured metric uses. The reconciler also names any other routing
protocol it finds in the table at startup.

On darwin there are no tables and no `rt_proto`, so ownership is by interface
and by shape: a route out of its own utun whose gateway is a link address naming
that interface. That condition is the whole guarantee: nothing else writes
routes out of our utun. Tailscale's `100.64.0.0/10` on its own utun has exactly
the shape described above, so a reconciler pointed at that interface would adopt
and withdraw it. Two things keep that from happening. The device is created by
asking for the next free unit, so it is never one another tunnel is already
using, and XNU allocates interface indices by incrementing a counter with no
free list, so a destroyed utun's index is never handed out again.

Interface-scoped routes are narrower still, because this reconciler installs a
scoped route for a source-specific announcement, and so do other tools. A macOS
host running Tailscale carries a scoped `255.255.255.255` entry with a link
gateway and `RTF_STATIC`, so a scoped route counts as this reconciler's only
when this process scoped that destination. One left behind by a crash is left
alone rather than deleted on a guess.

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
neither. There is a second-order effect too. Once the outgoing interface has no
address of a family, which happens on an IPv4-only network where the mesh
address is the box's only global IPv6, RFC 6724 rule 5 makes the mesh address a
candidate source for traffic that is not going through the mesh at all, and
those packets die at the first BCP 38 filter with nothing to show for it
locally.

An install that collides with a route another program holds is reported once and
left alone. darwin has no replace, and the collision does not resolve itself, so
the route stays in the diff and the install is attempted again on every pass,
silently after that first report. The reconcile line counts it as not installed
rather than as added, and says nothing at all about a pass that moved nothing.

Addresses are narrower still: only an address this process added is ever
removed, and one already on the link belongs to whoever put it there. That rule
has one consequence worth knowing about on a TUN the operator created rather
than one ranet-lite made, which is the only kind that outlives the process. An
instance killed outright leaves its addresses on the device, and the next one
finds them already there, so it never adds them, never records them as its own,
and never removes them, even on a clean shutdown. Its routes do come back, since
they carry the protocol marker that identifies them. The TUN is enslaved to a
VRF only while it has no master at all, so systemd-networkd keeps whatever it
already claimed. The device itself is created by asking for the next free unit,
so it never takes a name another tunnel is using.

`cap.egress` writes into the packet filter, where the same three rules hold. It
creates an nftables table named after this tool, one per address family, holding
one nat postrouting chain; that name is the whole of its ownership claim, as
`rt_proto` is the reconciler's. It writes only inside those tables, reads back
only rules it wrote, replaces the chain's contents in one transaction rather
than editing it rule by rule, so no packet is ever evaluated against half a
ruleset, and removes both tables at shutdown. A table left behind by an earlier
instance carries the same name and is adopted, then brought to what the
configuration now asks for, and one in a family the configuration no longer
covers is removed at startup rather than left translating under rules nothing is
maintaining.

Nothing here writes iptables. The two are separate registries in the kernel, an
`iptables-nft` rule is visible here as an ordinary nftables table, and the
conflicts everybody remembers between firewall managers are an iptables problem
this declines to join. A host still running legacy iptables is invisible to the
conflict report below for the same reason.

Other source translation at the same hook is reported rather than fought over.
Several nat postrouting chains coexist at `srcnat` priority, docker's and
Tailscale's among them, and the first one to translate a connection keeps it for
that connection's lifetime. Deleting a neighbor's rule to win that race would
break whatever installed it, so `status` and the scrape name the other chains
instead and leave them alone. Their rules and this one are usually disjoint,
since this one matches on the mesh device in both directions.

## Reloading

`SIGHUP` re-reads the config file and the registry and reconciles rather than
restarting. It applies the registry itself, the peers dialed, and the prefixes
originated, so a node joining or leaving the mesh costs one dialer instead of
dropping every SA this node is carrying. ranet's own `ExecReload` works the same
way, and it matters because the registry is rewritten every time any node joins.

A reload also decides which sessions stay. The registry is the trust root a
handshake is checked against, so a node taken out of it stops being carried:
every session whose authenticated peer the new registry no longer names is
closed, and the line naming it says so. A registry read mid-write fails to parse
rather than arriving empty, so the sweep never runs against half a file.

A session this node dialed also ends when its dialer does, and taking the peer
out of `peers:` stops that dialer. One the peer opened against this node's
`responder` survives, because nothing was dialing it.

Revocation tests whether the organization still names the node and its key still
parses, not which endpoint the peer asserted. Renumbering a serial is a registry
edit rather than a revocation, and a node whose own endpoints were renumbered
has done nothing to lose the session it is carrying.

Everything else is refused rather than applied, because a reload cannot reach
it. Identity, port, TUN device and local endpoints each change what peers have
already authenticated or what the dataplane is attached to. So does the private
key. It is read once at startup and the responder holds its own copy, so a
reload re-reads the file only to compare: a rotation is refused by name whether
it moved the path or rewrote the file in place, rather than reported as applied
while the node keeps signing with the key it started on. The `babel` block is
built into the speaker once, apart from the prefixes it originates, which a
reload does apply. The `kernel` block, including the addresses
`assign_originated` expands into, is read once at startup, and so is the
`cap.egress`: the capability owns the tables it created under the families the
old block named, and a new one applied here would leave the host holding rules
from a configuration nothing is running. The rekey and replay settings are
captured by a session when it is created, so applying them to new sessions alone
would leave the node running two policies at once. And `responder` decides
whether the node answers at all, which is wired up before the reload path
exists. A restart is the honest way to change any of them, and a reload that
fails validation changes nothing.

## Repository layout

A package outside `internal` is an API other programs may import, and carries a
package doc that says what a caller calls. The rule that decides membership is
mechanical: a package can only sit outside `internal` if everything it imports
does too, so the import graph fixes the order in which anything else follows.

- `control` is the control socket: its wire types, the reads, the five verbs
  that act on a running node, and the client the subcommands speak it with. It
  is the surface a control plane or a third-party monitor talks to, and it
  imports nothing else in this repository.
- `transport` is the shared UDP socket mux, separating IKE from ESP framing, and
  the one setting that keeps that socket off the routes the mesh installs. It
  imports nothing else in this repository.
- `esp` is userspace ESP AEAD encap and decap with anti-replay.
- `sadr` is the immutable source and destination routing trie, with snapshot
  iteration.
- `schema` is the scalar vocabulary a configuration file is written in: a
  duration, a prefix, an address, a routing table and one announcement, each
  carrying the decoder pair and the emptiness test that yaml, json and toml
  between them ask for. It imports nothing else in this repository.
- `srv6` is segment routing over IPv6 in userspace: the RFC 8754 header,
  H.Encaps, and the End and End.DT46 behaviors, taking bytes and returning bytes
  so that a caller acts on the header without a kernel. It imports `sadr` and
  `schema`.
- `ike` is the IKEv2 initiator and responder, one set of modern transforms and
  no others, negotiating the Child SA `esp` carries over a `transport` hub. It
  imports `esp`, `transport` and `schema`.

The rest is this program's own assembly, or is held inside by one import:

- `internal/client` owns the runtime, peer reconnection, and the ESP pipeline.
- `internal/netstack` owns the TUN device and the `(source, destination)` route
  table.
- `internal/babel` is the embedded Babel speaker.
- `internal/kernel` is the optional reconciler. It mirrors learned routes into a
  routing table it owns on linux, or on darwin into the single table that
  platform has, and assigns the TUN's addresses.
- `internal/packet` validates TUN and decrypted IP packets.
- `internal/registry` reads a ranet-compatible `registry.json` and Ed25519 key
  loading.
- `internal/config` is ranet-lite's own config format.
- `internal/egress` is the exit node and subnet router capability: the source
  translation, the nftables table it owns, and the advertisement it withholds
  while that table does not hold the rules the configuration asks for.
- `internal/notices` is the third-party notice file the binary carries.
- `internal/kernel/rules_linux.go` is the policy rules and the VRF, which exist
  on linux alone and are therefore optional halves of the platform rather than
  methods every backend stubs out.
- `cmd/ranet-lite` is the production binary, and the only thing under `cmd`.
- `internal/cmd/*` are the tools this tree runs on itself: `notices`, which
  regenerates the third-party notice file, and the standalone interop and
  smoke-test binaries used during development (IKE, ESP, babel tests). They are
  under `internal` so that nothing outside this repository can install them.

`internal/babel` and `internal/kernel` are the two worth promoting next, an RFC
8966 speaker with SADR and RTT and a route reconciler with real ownership
semantics on two platforms. Both are blocked on `internal/netstack`, the
daemon's dataplane, so moving them means promoting it too or cutting what each
takes from it down to an interface, which is a wider move than any of these.

The nix half follows the same layout as [inc](https://github.com/stepbrobd/inc),
over [autopilot](https://github.com/stepbrobd/autopilot), which loads `lib/` and
`modules/flake/` by directory so `flake.nix` names inputs and nothing else:

- `lib/` holds nix helpers, one per file, kebab-case on disk and camelCase in
  `lib`. They are adapted from inc and say so.
- `modules/flake/` holds one flake-parts module per output: `packages.nix`,
  `checks.nix`, `shell.nix`, `formatter.nix`, `overlays.nix`, `modules.nix`, and
  `integration.nix`, which holds the VM test helper the checks and the profiling
  packages share.
- `pkgs/` holds one directory per package, imported into `overlays.default` by
  `lib.importPackagesTree`. `pkgs.ranet-lite` is the daemon and
  `pkgs.iperf3-benchmark` is the patched iperf the namespace benchmark needs.
- `modules/nixos/` and `modules/darwin/` are the deployment modules, exported as
  `nixosModules.default` and `darwinModules.default`. See
  [Running it as a service](#running-it-as-a-service).
- `integration/` holds the NixOS VM tests and the namespace benchmark.

## Running it as a service

The nixos module runs the daemon from this flake's package, writes the config
file from `services.ranet-lite.settings`, and gives the control socket a
`RuntimeDirectory` and a group:

```nix
{
  imports = [ inputs.ranet-lite.nixosModules.default ];

  services.ranet-lite = {
    enable = true;
    group = "ranet-lite";
    settings = {
      node = {
        org = "example";
        name = "gateway";
      };
      auth = {
        key = "/var/lib/ranet-lite/key.pem";
        trust = "/var/lib/ranet-lite/trust.json";
      };
      link = {
        port = 13000;
        endpoints = [
          {
            serial = "0";
            family = "ip4";
          }
        ];
      };
    };
  };
}
```

`settings` is written to the store and is world readable there, so the key and
the trust document are named by path rather than carried inline. A config file
that must stay out of the store entirely is named by `configFile` instead.
`systemctl reload ranet-lite` sends SIGHUP, which reconciles against a rewritten
trust document without dropping an SA. A restart drops every one.

The nix-darwin module is the same options over `launchd.daemons`, with the log
file taking the place of the journal and `admin` as the default group, because
that is a group macOS already has and nothing here creates one. It was evaluated
by hand against nix-darwin, which produced the expected plist, and it has never
been loaded on a Mac. No check covers it: verifying it in CI would mean taking
nix-darwin as an input of this flake, which nothing else here needs.

## Testing

```sh
go test ./... -race
```

The unit tests need no privileges, with two exceptions: `internal/kernel` has
tests that write to a real routing table, and `internal/egress` one that writes
into a real packet filter. Both unshare a network namespace and refuse to
continue unless it is empty, and both skip unless run as root, on darwin unless
`RANET_LITE_DARWIN_NETTEST=1` is also set, because that machine is on a live
mesh.

`internal/kernel` names the machine it reads and writes, `kernel.Host`, so the
darwin backend can be driven without either. `internal/client`'s
`daemon_darwin_test.go` uses that to run a configuration file all the way to a
daemon against a recorded routing table: the transport binds, the underlay
writes the default its bound socket depends on, and the reconciler holds an
announced default out of the kernel until a session is live, all asserted on the
routes that arrive rather than on the calls that made them. It needs no
privilege, and the one thing it leaves with the running kernel is `IP_BOUND_IF`
on the transport's own UDP socket. The `netlink` VM check runs both binaries as
root against a real kernel, which is the only place the `nf_tables` encoding is
checked against something other than the decoder it was written beside.
Protocol-level interoperability is covered by the NixOS VM tests in
`modules/flake/checks.nix`. Each boots separate client and gateway VMs; the
client runs the packaged, user-facing `ranet-lite` binary with a real TUN
device, while the gateway runs `charon-systemd`/`swanctl`, BIRD, and iperf3. The
default test verifies an Ed25519-authenticated IKEv2 and Child SA negotiation
across asymmetric local and remote UDP ports, checks Babel route exchange in
both directions, and measures TCP bandwidth through the negotiated ESP tunnel:

```sh
nix build .#checks.x86_64-linux.integration -L
nix build .#checks.x86_64-linux.integration-multicore -L
nix build .#checks.x86_64-linux.responder -L
nix build .#checks.x86_64-linux.kernel -L
nix build .#checks.x86_64-linux.segments -L
nix build .#checks.x86_64-linux.egress -L
```

`responder` inverts the exchange: strongSwan dials and ranet-lite answers, which
upstream could not do at all, and the check asserts that ranet-lite never dials.
`kernel` exercises the route reconciler against a real table. `nixos-module`
boots nothing: it evaluates the nixos module into the unit systemd would run and
reads back the binary, the runtime directory and the group, since otherwise a
wrong option name in it is found by the first machine that imports it.

`egress` makes the client an exit node and boots a third machine behind it,
holding prefixes the gateway can reach through the mesh and no other way. It
asserts that the announcement reaches BIRD on the far side, that the machine
behind the exit sees the exit's own address on both families and never the mesh
address the packet started with, that the sweep recognizes its own rules rather
than rewriting them, that turning `net.ipv4.ip_forward` off withdraws the IPv4
advertisement and leaves the IPv6 one alone, and that a stop leaves no nftables
table behind.

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
stream counts, affinity, MTU, and replay windows identical between versions.
`--replay-window` sets it for every instance in the run, on both sides, and
defaults to 4096 rather than strongSwan's own 32 so replay drops are
distinguishable from processing limits. `--protocol udp --rate 10` offers an
aggregate 10 Gbit/s per direction with UDP GSO/GRO and 4 MiB iperf socket
buffers; inspect received throughput and loss, not just the offered rate. The
Nix development shell uses the `iperf3-benchmark` package, which changes
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
