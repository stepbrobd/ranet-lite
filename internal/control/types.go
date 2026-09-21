// Package control is the read-only view of a running node and the client that
// reads it. The daemon serves JSON over a unix socket and the same binary's
// subcommands render it, which is the answer to `birdc show babel neighbors`
// and `birdc show route` once Babel has moved out of BIRD.
//
// # Read-only
//
// Nothing here writes. A node's configuration comes from its file and a reload
// is SIGHUP, so the socket needs no authorization story beyond its mode: a
// reader learns the mesh's topology and this node's counters, and can change
// nothing. The handler refuses every method but GET for that reason, rather
// than leaving the rule implied by the absence of a route that would write.
//
// # Versioning
//
// Paths carry a /v0 prefix. The shape below is this repository's own and is
// consumed by this repository's own client, so v0 promises only that a client
// and a daemon from the same build agree. A field may be added at any time; a
// client ignores what it does not know.
package control

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"time"
)

// Paths the handler serves, named so the client and the server cannot drift.
const (
	PathStatus    = "/v0/status"
	PathNeighbors = "/v0/neighbors"
	PathRoutes    = "/v0/routes"
	PathSessions  = "/v0/sessions"
	PathPeers     = "/v0/peers"
)

// DefaultSocket is where the daemon listens and where the client looks. It is
// under /var/run rather than /run because darwin has only the former and linux
// resolves it to the latter, so one path serves both platforms.
const DefaultSocket = "/var/run/ranet-lite/control.sock"

// Source is everything the control surface reads. The runtime implements it.
// Each method takes the lock its own subsystem runs under and returns a value,
// so a handler never holds a lock while writing to a socket.
type Source interface {
	Status() Status
	Neighbors() []Neighbor
	Routes() []Route
	Sessions() []Session
	Peers() []Peer
}

// Duration is a time.Duration that reads as "4s" in JSON rather than as a
// count of nanoseconds, because the output of this package is read by people
// at least as often as by programs.
type Duration time.Duration

func (d Duration) MarshalJSON() ([]byte, error) { return json.Marshal(time.Duration(d).String()) }

func (d *Duration) UnmarshalJSON(b []byte) error {
	var text string
	if err := json.Unmarshal(b, &text); err != nil {
		return err
	}
	parsed, err := time.ParseDuration(text)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func (d Duration) String() string { return time.Duration(d).String() }

// Status is the node as a whole: who it is, what it is attached to, and the
// counts that say whether the mesh around it is healthy.
type Status struct {
	Version      string `json:"version"`
	Organization string `json:"organization"`
	CommonName   string `json:"common_name"`
	Port         uint16 `json:"port"`
	// Endpoints is this node's own local endpoints, "<serial>/<family>".
	Endpoints []string  `json:"endpoints"`
	TUN       string    `json:"tun"`
	MTU       int       `json:"mtu"`
	Queues    int       `json:"queues"`
	StartedAt time.Time `json:"started_at"`
	Uptime    Duration  `json:"uptime"`
	// Responder, FullMesh and NoTransit are the three settings that decide
	// which node this is on a fleet, so they are reported rather than left to
	// be read back off the config file on a machine an operator is not on.
	Responder bool `json:"responder"`
	FullMesh  bool `json:"full_mesh"`
	NoTransit bool `json:"no_transit"`
	// Forwarding is the kernel's, per family. A node that redistributes with
	// forwarding off attracts traffic it drops and nothing tells the sender,
	// so the answer belongs next to NoTransit rather than in a sysctl an
	// operator has to think to check.
	ForwardsIPv4 bool         `json:"forwards_ipv4"`
	ForwardsIPv6 bool         `json:"forwards_ipv6"`
	Registry     RegistryInfo `json:"registry"`
	Kernel       KernelStatus `json:"kernel"`
	Counts       Counts       `json:"counts"`
	ESP          ESPCounters  `json:"esp"`
	Originate    []Originated `json:"originate"`
	// Segments lists the addresses this node answers for as a waypoint or an
	// exit, each written as the address and the behavior. It is absent on a
	// node that configures no segment routing, which is most of them.
	Segments []string `json:"segments,omitempty"`
	// Steering is the policies deciding which of this node's own packets go
	// through a segment list, in the order they were written.
	Steering []string `json:"steering,omitempty"`
	// SegmentCounters is always present, zeroes included. Omitting it while
	// nothing had happened yet would read the same as a node with no segment
	// routing at all, and those are the two states a reader is trying to tell
	// apart.
	SegmentCounters SegmentCounters `json:"segment_counters"`
}

// SegmentCounters is this node's segment routing, counted since startup.
// Forwarded is packets an End sent on to their next segment, Delivered is
// packets an End.DT46 took the outer header off and handed to the stack, and
// Dropped is packets addressed to one of this node's segments that it would
// not act on.
type SegmentCounters struct {
	Forwarded uint64 `json:"forwarded"`
	Delivered uint64 `json:"delivered"`
	Dropped   uint64 `json:"dropped"`
	// Steered counts this node's own packets a policy encapsulated, Unsteered
	// the ones a policy claimed and could not, and Unrouted the ones it
	// encapsulated toward a first segment the mesh had no route to. Both
	// failures drop the packet, because a policy here selects an exit and the
	// route it overrides puts the packet out of another node under a source
	// that node does not announce.
	Steered   uint64 `json:"steered"`
	Unsteered uint64 `json:"unsteered"`
	Unrouted  uint64 `json:"unrouted"`
	// Answered counts the ICMP errors sent for refused packets, which is the
	// half of Dropped whose sender was told why.
	Answered uint64 `json:"answered"`
}

// RegistryInfo is the trust root as this node last read it. A reload replaces
// it, so ReadAt tells a stale registry from one that never loaded.
type RegistryInfo struct {
	Path          string    `json:"path"`
	Organizations int       `json:"organizations"`
	Nodes         int       `json:"nodes"`
	ReadAt        time.Time `json:"read_at"`
}

// KernelStatus is the route reconciler: what it was configured to own, and
// what its last pass did. Installed counts the routes the kernel holds for it,
// and Skipped the ones the platform cannot represent or another writer already
// holds, which is the number that explains a prefix the mesh has and the
// kernel does not.
type KernelStatus struct {
	Enabled  bool   `json:"enabled"`
	Where    string `json:"where,omitempty"`
	Table    uint32 `json:"table,omitempty"`
	Protocol uint8  `json:"protocol,omitempty"`
	Metric   uint32 `json:"metric,omitempty"`
	VRF      string `json:"vrf,omitempty"`
	// PassAt is zero until the first pass has run.
	PassAt    time.Time `json:"pass_at,omitzero"`
	Installed int       `json:"installed"`
	Skipped   int       `json:"skipped"`
	Added     int       `json:"added"`
	Removed   int       `json:"removed"`
	Err       string    `json:"err,omitempty"`
}

// Counts is the mesh in six numbers, which is the first thing to read when
// something is wrong.
type Counts struct {
	// Dialers is the peer loops running, which is smaller than the peers
	// command lists: a peer the registry names without a dialable address
	// never gets one.
	Dialers        int `json:"dialers"`
	Sessions       int `json:"sessions"`
	Neighbors      int `json:"neighbors"`
	NeighborsAlive int `json:"neighbors_alive"`
	Prefixes       int `json:"prefixes"`
	Selected       int `json:"selected"`
	Originated     int `json:"originated"`
}

// ESPCounters is the dataplane, counted since startup.
type ESPCounters struct {
	InboundPackets uint64 `json:"inbound_packets"`
	InboundDropped uint64 `json:"inbound_dropped"`
	ReceiveDropped uint64 `json:"receive_dropped"`
	ReceiveRefused uint64 `json:"receive_refused"`
	Keepalives     uint64 `json:"keepalives"`
}

// Originated is one prefix this node announces itself, with the source prefix
// an exit's default carries.
type Originated struct {
	Prefix netip.Prefix `json:"prefix"`
	From   netip.Prefix `json:"from,omitzero"`
}

func (o Originated) String() string {
	if o.From.IsValid() {
		return fmt.Sprintf("%s from %s", o.Prefix, o.From)
	}
	return o.Prefix.String()
}

// Neighbor is one Babel neighbor, which `birdc show babel neighbors` reports,
// plus the two dataplane counters BIRD has no equivalent of.
type Neighbor struct {
	Peer    string     `json:"peer"`
	Address netip.Addr `json:"address,omitzero"`
	Alive   bool       `json:"alive"`
	// Cost is this node's cost for the link, where 65535 is infinity.
	Cost uint16 `json:"cost"`
	// ReportedCost is the cost the neighbor advertises back in its IHU, so a
	// link that works in one direction only can be told from one that works in
	// neither. It is absent until an IHU has arrived.
	ReportedCost *uint16 `json:"reported_cost,omitempty"`
	// RTT is absent until a timestamped IHU has been received.
	RTT     *Duration `json:"rtt,omitempty"`
	Routes  int       `json:"routes"`
	Expires Duration  `json:"expires"`
	// Dropped is packets this node's dataplane refused to queue for the peer,
	// and SendFailed packets the transport lost after they were sealed. The
	// first is this node running out of room and the second is the link.
	Dropped    uint64 `json:"dropped"`
	SendFailed uint64 `json:"send_failed"`
}

// Route is one entry of the Babel route table, selected or not, which is
// `birdc show route` for the mesh. Via is empty when the prefix is held
// unreachable, which a retraction leaves behind so a packet does not follow a
// shorter prefix instead.
type Route struct {
	Destination netip.Prefix `json:"destination"`
	From        netip.Prefix `json:"from,omitzero"`
	Via         string       `json:"via,omitempty"`
	// Metric is the selected route's cost, 65535 for a retraction.
	Metric   uint16 `json:"metric"`
	RouterID string `json:"router_id,omitempty"`
	Seqno    uint16 `json:"seqno"`
	// Candidates is how many neighbors advertise this prefix, so a prefix with
	// one path can be told from one with a dozen.
	Candidates int  `json:"candidates"`
	Originated bool `json:"originated"`
}

// Session is one live IKE SA. Path names the local and remote endpoint pair
// rather than only the peer, because a node reaching one peer over both
// address families holds a session on each.
type Session struct {
	Path   string `json:"path"`
	Peer   string `json:"peer"`
	Remote string `json:"remote,omitempty"`
	// Preferred is whether this node is the end both sides agreed should be
	// the initiator, which is the rule that settles a simultaneous dial.
	Preferred bool      `json:"preferred"`
	Active    bool      `json:"active"`
	LocalSPI  uint32    `json:"local_spi"`
	RemoteSPI uint32    `json:"remote_spi"`
	StartedAt time.Time `json:"started_at"`
	Age       Duration  `json:"age"`
	// Idle is how long since the peer last proved it is still there, which is
	// what dead peer detection acts on.
	Idle Duration `json:"idle"`
}

// Peer is one node this one dials, with its dialer's state. A responder-only
// session does not appear here, because nothing local is dialing it; it
// appears under Sessions like any other.
type Peer struct {
	Path         string `json:"path"`
	Organization string `json:"organization"`
	CommonName   string `json:"common_name"`
	SerialNumber string `json:"serial_number,omitempty"`
	// Connected is whether a session holds this path, from either direction.
	Connected bool `json:"connected"`
	// Generated marks a peer that full_mesh derived from the registry rather
	// than one written in the config file.
	Generated bool `json:"generated"`
}
