// Package control is the wire format of a running node's live view and of the
// few verbs that act on it, the client that speaks it and the server that
// answers. The daemon serves JSON over a unix socket and the same binary's
// subcommands render it, which is the answer to `birdc show babel neighbors`
// and `birdc show route` once Babel has moved out of BIRD.
//
// # What a caller uses
//
// A monitor or a control plane dials [DefaultSocket] with [Dial] and reads
// [Client.Status], [Client.Neighbors], [Client.Routes], [Client.Sessions] and
// [Client.Peers], each of which returns the types declared here. A program
// that holds a node of its own instead implements [Source] and hands it to
// [Serve] over a listener from [Listen]. The daemon in this repository is one
// such program and takes no privileged path of its own. The Render functions
// write the same values as the text the subcommands print.
//
// A Source that also implements [Sink] serves the four operational verbs as
// well, and one that does not serves the reads alone and refuses every write
// by name rather than by a missing route.
//
// Nothing outside this package is needed to speak the protocol: the types are
// plain structs over [net/netip] addresses and a [Duration] that marshals as a
// Go duration string, and the paths are named constants. This package imports
// nothing else in this repository, so a caller takes it without taking the
// daemon.
//
// # What the socket grants
//
// The reads carry the mesh's topology and this node's counters and change
// nothing at all. The writes in [Sink] stop and start a subsystem, drop the
// sessions this node holds for one peer so its dialer opens them again,
// replace a Child SA, and re-read the configuration file. None of them holds
// state of its own past the process, and none of them touches the
// configuration: the file stays its only entry point.
//
// A node's configuration comes from its file, so the socket's mode is the
// whole authorization story, and every verb here stays inside it. Each one
// acts on something the file already decides -- cap.table, cap.segment's
// steering, link.listen, the peers list, and the file itself -- so whoever
// may edit the file could already ask for it, by editing and restarting if
// not by editing and sending SIGHUP. The socket grants nothing the file's
// permissions did not.
//
// That is the line a verb has to stay inside. One that changed something the
// file cannot express, a new peer or a key or an address, would put a grant
// on the socket the file's permissions do not carry, and it is refused on
// those grounds rather than admitted with an authorization check of its own.
// [Subsystem] is a closed set for the same reason.
//
// The two halves are told apart by method rather than by path. A read answers
// GET and HEAD and nothing else, so a caller that reaches a write path with a
// GET is refused rather than acted on; a write answers POST alone, because a
// second rekey is a second exchange rather than the same one repeated.
//
// # Versioning
//
// Paths carry a /v0 prefix. v0 promises that a client and a daemon built from
// the same revision agree, and nothing wider: a field may be added at any
// time, and a caller ignores what it does not know rather than refusing it. A
// removal or a change of meaning takes a new prefix, so a caller pinned to
// /v0 keeps reading what it read.
package control

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"time"
)

// Paths the handler serves, named so the client and the server cannot drift.
// The reads in the first group answer a GET and the verbs in the second a
// POST; see the package doc for why the method rather than the prefix
// separates them.
const (
	PathStatus    = "/v0/status"
	PathNeighbors = "/v0/neighbors"
	PathRoutes    = "/v0/routes"
	PathSessions  = "/v0/sessions"
	PathPeers     = "/v0/peers"
	PathMetrics   = "/v0/metrics"

	PathDisable = "/v0/disable"
	PathEnable  = "/v0/enable"
	PathRedial  = "/v0/redial"
	PathRekey   = "/v0/rekey"
	PathReload  = "/v0/reload"
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
	// Metrics writes the Prometheus text exposition format. It is served here
	// as well as on the metrics listener, so a node can be scraped by hand
	// without an operator having to bind a port to do it, and it is written
	// rather than returned because the daemon already renders it that way.
	// The handler writes into a buffer first, so a slow reader on the socket
	// does not hold whatever locks a render takes.
	Metrics(io.Writer)
}

// Subsystem names one part of a node that can be stopped and started again.
// The set is closed and stays closed: each of the three is a block of the
// configuration file, so stopping one asks for nothing the file could not say,
// and a name outside the set is refused rather than reaching for whatever a
// later runtime happens to call itself.
type Subsystem string

const (
	// SubsystemReconciler is the cap.table route reconciler. Stopping it
	// withdraws every route, address and rule it installed, the same as
	// `birdc disable` on a kernel protocol while Babel lived in BIRD.
	SubsystemReconciler Subsystem = "reconciler"
	// SubsystemSteering is cap.segment's steer policies, the decision to send
	// this node's own packets through a segment list. Stopping it sends them
	// by the route table instead, which is the node without the policies.
	SubsystemSteering Subsystem = "steering"
	// SubsystemResponder is link.listen, answering peers that dial in.
	// Stopping it leaves the sessions this node already holds alone, dialed
	// and answered alike, and refuses the next handshake.
	SubsystemResponder Subsystem = "responder"
)

// Subsystems is the closed set, in the order a usage line names them.
var Subsystems = []Subsystem{SubsystemReconciler, SubsystemSteering, SubsystemResponder}

// SubsystemNames is the same set as plain strings, for a usage line and for
// shell completion.
func SubsystemNames() []string {
	out := make([]string, 0, len(Subsystems))
	for _, name := range Subsystems {
		out = append(out, string(name))
	}
	return out
}

// Request is the body of a write. One shape serves every verb, and each verb
// reads the fields it needs: a field another verb fills is ignored rather than
// refused, so a client and a daemon built from different revisions still
// speak. An empty body decodes as the zero value, and reload is asked with one.
type Request struct {
	Subsystem Subsystem `json:"subsystem,omitempty"`
	Peer      string    `json:"peer,omitempty"`
	All       bool      `json:"all,omitempty"`
}

// Result is the answer to a write. Acted names what the verb reached, one
// entry per subsystem or per path, so a script sees the same list the sentence
// summarizes. Detail is that sentence, written once here rather than once in
// the daemon's log and again in the subcommand.
type Result struct {
	Acted  []string `json:"acted,omitempty"`
	Detail string   `json:"detail"`
}

// Sink is the write path, and is optional: [Handler] serves these verbs for a
// [Source] that implements it and refuses them by name for one that does not.
//
// Every method reports what it reached, or an error naming what this node does
// not run. A verb that found nothing is an error rather than a quiet success,
// because an operator told "steering is off" by a node that never steered has
// been told nothing.
type Sink interface {
	// SetSubsystem stops or starts one subsystem. The state lives in the
	// process, so a restart returns to whatever the file says and a reload
	// leaves it as an operator set it: a registry rewrite arrives on every
	// node that joins the mesh, and re-enabling on one would undo a decision
	// made minutes earlier.
	SetSubsystem(name Subsystem, on bool) (Result, error)
	// Redial drops the sessions this node holds for one peer and sets its
	// dialers going again at once rather than after the reconnect delay. It is
	// the answer to a peer that holds a session this node no longer has, on
	// the side that can act.
	Redial(peer string) (Result, error)
	// Rekey asks one peer's sessions, or every session, to replace their Child
	// SA. The exchange runs on its own and the new SPIs appear under
	// [Client.Sessions]; the answer says how many were asked.
	Rekey(peer string, all bool) (Result, error)
	// Reload re-reads the configuration file and the trust document it names,
	// as SIGHUP does, so a supervisor is not the only way to ask.
	Reload() (Result, error)
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
	Egress       EgressStatus `json:"egress"`
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
	// Disabled names the subsystems somebody stopped over the control socket,
	// and is absent where none is. A node whose file says it reconciles routes
	// and which is not reconciling them says so here and nowhere else, so this
	// is the field that keeps a disable from being invisible to whoever comes
	// after.
	Disabled []Subsystem `json:"disabled,omitempty"`
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
	// L3mdevAccept is whether a socket outside the VRF is matched by traffic
	// arriving through it, which is off by default and decides whether
	// anything on this node can use a mesh address at all. Nil where no VRF is
	// configured, since the question does not arise.
	L3mdevAccept *bool `json:"l3mdev_accept,omitempty"`
	// PassAt is zero until the first pass has run.
	PassAt    time.Time `json:"pass_at,omitzero"`
	Installed int       `json:"installed"`
	Skipped   int       `json:"skipped"`
	Added     int       `json:"added"`
	Removed   int       `json:"removed"`
	Err       string    `json:"err,omitempty"`
}

// EgressStatus is the exit node and subnet router capability: what this node
// was configured to carry, what it is carrying right now, and the difference
// between the two.
//
// Advertise and Announced are separate fields because they disagree exactly
// when something is wrong. A prefix is announced only while its translation
// rule is installed and the kernel forwards its family, so a configured prefix
// missing from Announced is this node declining to attract traffic it would
// have to drop, and it is the line to read when a customer's exit node has
// stopped being selected.
type EgressStatus struct {
	Enabled bool `json:"enabled"`
	// Where names the tables this node owns, as the backend spells them.
	Where string `json:"where,omitempty"`
	// Source4 and Source6 are the address a translated packet leaves under,
	// or "auto" where the host's own routes decide it per packet.
	Source4 string `json:"source4,omitempty"`
	Source6 string `json:"source6,omitempty"`
	// Return is whether this node also translates into the mesh, which a
	// subnet router needs and an exit node does not.
	Return    bool           `json:"return,omitempty"`
	Advertise []netip.Prefix `json:"advertise,omitempty"`
	Announced []netip.Prefix `json:"announced,omitempty"`
	// PassAt is zero until the first pass has run.
	PassAt    time.Time `json:"pass_at,omitzero"`
	Installed int       `json:"installed"`
	// Flows counts the connections the rules have translated. A nat chain is
	// consulted once per connection and never again, so this is flows rather
	// than packets, and Bytes is the first packet of each.
	Flows uint64 `json:"flows"`
	Bytes uint64 `json:"bytes"`
	// Conflicts names other source translation at the same hook, which is
	// reported rather than fought over: the first chain to translate a
	// connection keeps it.
	Conflicts []string `json:"conflicts,omitempty"`
	Err       string   `json:"err,omitempty"`
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
