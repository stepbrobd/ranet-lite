package client

import (
	"encoding/hex"
	"slices"
	"strings"
	"time"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/control"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/srv6"
	"github.com/NickCao/ranet-lite/internal/version"
)

// This file is the runtime's side of the control socket. Every method reads
// live state under whatever lock owns it and returns a value, so a slow
// reader on the socket never holds the dataplane's lock.
//
// Nothing here writes. The configuration's only entry points stay the file and
// SIGHUP, which is why the socket carries no authorization beyond its mode.

// SetKernelStatus hands the control surface the route reconciler's own view of
// its last pass. The reconciler is built by the command rather than here,
// because it owns the kernel and this owns the mesh, so the command supplies
// the reader once it exists. Without it the reconciler reports as off, which
// is the honest answer for a node configuring its routes externally.
func (c *Client) SetKernelStatus(read func() control.KernelStatus) {
	c.kernelStatus.Store(&read)
}

func (c *Client) Status() control.Status {
	cfg := c.config()
	reg := c.registry()
	stats := c.speaker.Stats()
	alive := 0
	for _, neighbor := range stats.Neighbors {
		if neighbor.Alive {
			alive++
		}
	}
	nodes := 0
	for _, org := range reg {
		nodes += len(org.Nodes)
	}
	forwardsV4, forwardsV6 := forwardingEnabled()
	endpoints := make([]string, 0, len(cfg.Endpoints))
	for _, endpoint := range cfg.Endpoints {
		endpoints = append(endpoints, endpoint.SerialNumber+"/"+endpoint.AddressFamily)
	}
	originate := c.speaker.Originated()
	announced := make([]control.Originated, 0, len(originate))
	for _, route := range originate {
		announced = append(announced, control.Originated{Prefix: route.Destination, From: route.Source})
	}
	return control.Status{
		Version:      version.Value,
		Organization: cfg.Organization,
		CommonName:   cfg.CommonName,
		Port:         cfg.Port,
		Endpoints:    endpoints,
		TUN:          c.Mesh.Name,
		MTU:          c.Mesh.MTU(),
		Queues:       c.Mesh.QueueCount(),
		StartedAt:    c.started,
		Uptime:       control.Duration(time.Since(c.started)),
		Responder:    cfg.Responder,
		FullMesh:     cfg.FullMesh,
		NoTransit:    cfg.Babel.NoTransit,
		ForwardsIPv4: forwardsV4,
		ForwardsIPv6: forwardsV6,
		Registry: control.RegistryInfo{
			Path:          cfg.Registry,
			Organizations: len(reg),
			Nodes:         nodes,
			ReadAt:        c.registryReadAt(),
		},
		Kernel: c.kernel(),
		Counts: control.Counts{
			Dialers:        c.dialerCount(),
			Sessions:       len(c.sessions.paths()),
			Neighbors:      len(stats.Neighbors),
			NeighborsAlive: alive,
			Prefixes:       stats.Prefixes,
			Selected:       stats.Selected,
			Originated:     stats.Originated,
		},
		ESP: control.ESPCounters{
			InboundPackets: c.inboundPackets.Load(),
			InboundDropped: c.inboundDropped.Load(),
			ReceiveDropped: c.hubDropped(),
			ReceiveRefused: c.hubRefused(),
			Keepalives:     c.hubKeepalives(),
		},
		Originate:       announced,
		Segments:        segmentText(c.Mesh.Segments()),
		Steering:        c.Mesh.Steering().Entries(),
		SegmentCounters: segmentCounters(c.Mesh.SegmentCounters()),
	}
}

// segmentCounters carries the dataplane's counters onto the wire. The two
// structs are written out rather than converted, so adding a field to one
// without the other is a compile error rather than a number that silently
// stops being reported.
func segmentCounters(counters netstack.SegmentCounters) control.SegmentCounters {
	return control.SegmentCounters{
		Forwarded: counters.Forwarded,
		Delivered: counters.Delivered,
		Dropped:   counters.Dropped,
		Steered:   counters.Steered,
		Unsteered: counters.Unsteered,
	}
}

// segmentText is the local segment table as an operator reads it, and nil on a
// node that configures none so the field is absent rather than empty.
func segmentText(table *srv6.LocalTable) []string {
	segments := table.Segments()
	if len(segments) == 0 {
		return nil
	}
	out := make([]string, 0, len(segments))
	for _, segment := range segments {
		out = append(out, segment.String())
	}
	return out
}

// kernel reports the reconciler, or that there is none. The configured half
// comes from the command through SetKernelStatus as well, because a config
// block that failed validation never became a reconciler and reporting its
// fields would describe a table nobody is writing.
func (c *Client) kernel() control.KernelStatus {
	if read := c.kernelStatus.Load(); read != nil {
		return (*read)()
	}
	return control.KernelStatus{}
}

func (c *Client) registryReadAt() time.Time {
	if at := c.regReadAt.Load(); at != 0 {
		return time.Unix(0, at)
	}
	return time.Time{}
}

func (c *Client) dialerCount() int {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	return len(c.dialers)
}

func (c *Client) Neighbors() []control.Neighbor {
	stats := c.speaker.Stats()
	out := make([]control.Neighbor, 0, len(stats.Neighbors))
	for _, neighbor := range stats.Neighbors {
		entry := control.Neighbor{
			Peer:       neighbor.Peer,
			Address:    neighbor.Addr,
			Alive:      neighbor.Alive,
			Cost:       neighbor.Cost,
			Routes:     neighbor.Routes,
			Expires:    control.Duration(neighbor.Expires),
			Dropped:    neighbor.Dropped,
			SendFailed: neighbor.SendFailed,
		}
		// Both are pointers on the wire rather than a zero, because zero is a
		// cost a link can genuinely have and a round trip a loopback peer
		// genuinely measures, and "not measured yet" has to read differently
		// from "measured, and it is zero".
		if neighbor.HaveReportedCost {
			cost := neighbor.ReportedCost
			entry.ReportedCost = &cost
		}
		if neighbor.HaveRTT {
			rtt := control.Duration(neighbor.RTT)
			entry.RTT = &rtt
		}
		out = append(out, entry)
	}
	return out
}

func (c *Client) Routes() []control.Route {
	dump := c.speaker.RouteDump()
	out := make([]control.Route, 0, len(dump))
	for _, route := range dump {
		out = append(out, control.Route{
			Destination: route.Destination,
			From:        route.Source,
			Via:         route.Via,
			Metric:      route.Metric,
			RouterID:    routerID(route),
			Seqno:       route.Seqno,
			Candidates:  route.Candidates,
			Originated:  route.Originated,
		})
	}
	return out
}

// routerID is the selected route's origin in hex, and empty where there is no
// selection: the zero router id is a value a peer could in principle send, so
// printing it for a prefix nobody offers would read as an origin.
func routerID(route babel.RouteStat) string {
	if route.Via == "" {
		return ""
	}
	return hex.EncodeToString(route.RouterID[:])
}

func (c *Client) Sessions() []control.Session {
	live := c.sessions.snapshot()
	out := make([]control.Session, 0, len(live))
	for _, session := range live {
		local, remote := session.session.ChildSPIs()
		started := session.session.StartedAt()
		entry := control.Session{
			Path:      session.path,
			Peer:      peerName(session.peer),
			Preferred: session.preferred,
			Active:    session.session.Active(),
			LocalSPI:  local,
			RemoteSPI: remote,
			StartedAt: started,
			Age:       control.Duration(time.Since(started)),
			Idle:      control.Duration(session.session.Idle()),
		}
		if endpoint := session.session.Mux().Endpoint(); endpoint != nil {
			entry.Remote = endpoint.AddrPort().String()
		}
		out = append(out, entry)
	}
	slices.SortFunc(out, func(a, b control.Session) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// peerName is the identity a session authenticated, or empty for one adopted
// without one, which only a test does.
func peerName(id ike.Identity) string {
	if id.Organization == "" && id.CommonName == "" {
		return ""
	}
	return id.Organization + "/" + id.CommonName
}

func (c *Client) Peers() []control.Peer {
	cfg := c.config()
	peers := effectivePeers(cfg, c.registry())
	// A peer past the configured list was derived from the registry by
	// full_mesh; effectivePeers keeps the configured ones first.
	configured := len(cfg.Peers)
	live := c.sessions.snapshot()
	out := make([]control.Peer, 0, len(peers)*len(cfg.Endpoints))
	for _, local := range cfg.Endpoints {
		for i, peer := range peers {
			out = append(out, control.Peer{
				Path:         peerPath(peer, local),
				Organization: peer.Organization,
				CommonName:   peer.CommonName,
				SerialNumber: peer.SerialNumber,
				Connected:    connected(live, peer, local),
				Generated:    i >= configured,
			})
		}
	}
	slices.SortFunc(out, func(a, b control.Peer) int { return strings.Compare(a.Path, b.Path) })
	return out
}

// connected reports whether a session covers one dialed pair. It matches on
// the authenticated identity and on the local endpoint the session name ends
// with, rather than on the dial path: a peer generated by full_mesh pins no
// serial number, while the session is named after the endpoint that answered,
// so the two strings differ for exactly the peers full_mesh produces.
func connected(live []liveSessionView, peer config.Peer, local config.Endpoint) bool {
	suffix := "@" + local.SerialNumber
	for _, session := range live {
		if session.peer.Organization != peer.Organization || session.peer.CommonName != peer.CommonName {
			continue
		}
		if strings.HasSuffix(session.path, suffix) {
			return true
		}
	}
	return false
}
