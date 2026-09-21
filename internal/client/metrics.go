package client

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"
)

// Metrics replaces what prometheus-bird-exporter reported while Babel lived in
// BIRD. It is the Prometheus text exposition format, written by hand rather
// than through a client library so the dependency list stays short.
//
// Everything here is read from live state at scrape time rather than sampled
// on a timer, so a scrape reflects the instant it happened.
func (c *Client) Metrics(w io.Writer) {
	babel := c.speaker.Stats()
	sessions := c.sessions.paths()

	fmt.Fprint(w, "# HELP ranet_lite_babel_neighbor_up Whether a babel neighbor is alive.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_babel_neighbor_up gauge\n")
	for _, neighbor := range babel.Neighbors {
		fmt.Fprintf(w, "ranet_lite_babel_neighbor_up{peer=\"%s\"} %d\n", label(neighbor.Peer), boolValue(neighbor.Alive))
	}
	fmt.Fprint(w, "# HELP ranet_lite_babel_neighbor_cost Link cost to a babel neighbor, where 65535 is infinity.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_babel_neighbor_cost gauge\n")
	for _, neighbor := range babel.Neighbors {
		fmt.Fprintf(w, "ranet_lite_babel_neighbor_cost{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Cost)
	}
	fmt.Fprint(w, "# HELP ranet_lite_babel_routes_received Routes learned from one neighbor, selected or not.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_babel_routes_received gauge\n")
	for _, neighbor := range babel.Neighbors {
		fmt.Fprintf(w, "ranet_lite_babel_routes_received{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Routes)
	}
	fmt.Fprint(w, "# HELP ranet_lite_peer_send_dropped_total Packets a peer did not send: no transmission slot free, the peer closing, or its outbound SA unable to give out a sequence range.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_peer_send_dropped_total counter\n")
	for _, neighbor := range babel.Neighbors {
		fmt.Fprintf(w, "ranet_lite_peer_send_dropped_total{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.Dropped)
	}
	fmt.Fprint(w, "# HELP ranet_lite_peer_send_failed_total Packets a peer sealed and the transport then lost.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_peer_send_failed_total counter\n")
	for _, neighbor := range babel.Neighbors {
		fmt.Fprintf(w, "ranet_lite_peer_send_failed_total{peer=\"%s\"} %d\n", label(neighbor.Peer), neighbor.SendFailed)
	}
	fmt.Fprint(w, "# HELP ranet_lite_babel_routes_selected Routes currently installed in the forwarding table.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_babel_routes_selected gauge\n")
	fmt.Fprintf(w, "ranet_lite_babel_routes_selected %d\n", babel.Selected)
	fmt.Fprint(w, "# HELP ranet_lite_babel_routes_originated Prefixes this node announces itself.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_babel_routes_originated gauge\n")
	fmt.Fprintf(w, "ranet_lite_babel_routes_originated %d\n", babel.Originated)

	fmt.Fprint(w, "# HELP ranet_lite_session_up Whether an IKE session is established for one path.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_session_up gauge\n")
	for _, path := range sessions {
		fmt.Fprintf(w, "ranet_lite_session_up{path=\"%s\"} 1\n", label(path))
	}
	fmt.Fprint(w, "# HELP ranet_lite_sessions Established IKE sessions.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_sessions gauge\n")
	fmt.Fprintf(w, "ranet_lite_sessions %d\n", len(sessions))

	// Authenticated and validated, which is not the same as delivered: the
	// count includes babel control packets the speaker consumed, RFC 4303
	// section 2.6 dummy packets that carry nothing, and packets a closing mesh
	// discards. A dashboard already references the name, so the help text
	// carries the qualification instead.
	fmt.Fprint(w, "# HELP ranet_lite_esp_inbound_packets_total ESP packets that authenticated and passed validation, including babel control traffic and dummy packets.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_esp_inbound_packets_total counter\n")
	fmt.Fprintf(w, "ranet_lite_esp_inbound_packets_total %d\n", c.inboundPackets.Load())
	fmt.Fprint(w, "# HELP ranet_lite_esp_inbound_dropped_total ESP packets that failed to decrypt or validate.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_esp_inbound_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_esp_inbound_dropped_total %d\n", c.inboundDropped.Load())

	c.renderReceiveCounters(w)
	c.renderSegmentCounters(w)
	c.renderKernel(w)
	c.renderEgress(w)
}

// renderEgress writes the exit node and subnet router capability. A node that
// carries nothing for anybody writes none of it, as with the reconciler.
//
// The advertised and announced counts are separate series rather than one
// gauge and a label, because their difference is the alert: a prefix is
// announced only while its rule is installed and the kernel forwards it, so
// announced below advertised is this node declining to attract traffic it
// would drop, and no peer can see that from its own end.
func (c *Client) renderEgress(w io.Writer) {
	egress := c.egress()
	if !egress.Enabled {
		return
	}
	fmt.Fprint(w, "# HELP ranet_lite_egress_rules_installed Source translation rules the host holds for this node as of its last pass.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_egress_rules_installed gauge\n")
	fmt.Fprintf(w, "ranet_lite_egress_rules_installed %d\n", egress.Installed)
	fmt.Fprint(w, "# HELP ranet_lite_egress_prefixes Prefixes this node offers to carry, and the ones it is announcing: announcing fewer is this node withholding a prefix whose rule is not installed or whose family the kernel will not forward.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_egress_prefixes gauge\n")
	fmt.Fprintf(w, "ranet_lite_egress_prefixes{state=\"advertised\"} %d\n", len(egress.Advertise))
	fmt.Fprintf(w, "ranet_lite_egress_prefixes{state=\"announced\"} %d\n", len(egress.Announced))
	fmt.Fprint(w, "# HELP ranet_lite_egress_flows_total Connections the translation rules have rewritten. A nat chain is consulted once per connection, so this counts flows rather than packets.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_egress_flows_total counter\n")
	fmt.Fprintf(w, "ranet_lite_egress_flows_total %d\n", egress.Flows)
	fmt.Fprint(w, "# HELP ranet_lite_egress_conflicts Other source translation at the same hook, which the first chain to claim a connection keeps.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_egress_conflicts gauge\n")
	fmt.Fprintf(w, "ranet_lite_egress_conflicts %d\n", len(egress.Conflicts))
	fmt.Fprint(w, "# HELP ranet_lite_egress_pass_timestamp_seconds When the last pass finished, and zero before the first one has.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_egress_pass_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "ranet_lite_egress_pass_timestamp_seconds %d\n", unixOrZero(egress.PassAt))
	fmt.Fprint(w, "# HELP ranet_lite_egress_pass_failed Whether the last pass reported an error.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_egress_pass_failed gauge\n")
	fmt.Fprintf(w, "ranet_lite_egress_pass_failed %d\n", boolValue(egress.Err != ""))
}

// renderSegmentCounters writes the segment routing half. Nothing exported it
// before, and on a fleet node there was nothing to export: the behaviors were
// seg6local routes and the kernel counted them. Here the dataplane is this
// process, so a scrape is the only place from which a steered path that
// stopped working can be seen.
//
// What this node did for a peer and what it did with its own traffic are
// separate series, because they fail for different reasons: a rising dropped
// means peers are sending headers this node will not act on, and a rising
// steer_dropped means this node's own policy is pointing somewhere the mesh
// cannot reach.
func (c *Client) renderSegmentCounters(w io.Writer) {
	segments := c.Mesh.SegmentCounters()
	fmt.Fprint(w, "# HELP ranet_lite_segments_forwarded_total Packets an End behavior sent on to their next segment.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_segments_forwarded_total counter\n")
	fmt.Fprintf(w, "ranet_lite_segments_forwarded_total %d\n", segments.Forwarded)
	fmt.Fprint(w, "# HELP ranet_lite_segments_delivered_total Packets an End.DT46 behavior took the outer header off and handed to the stack.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_segments_delivered_total counter\n")
	fmt.Fprintf(w, "ranet_lite_segments_delivered_total %d\n", segments.Delivered)
	fmt.Fprint(w, "# HELP ranet_lite_segments_dropped_total Packets addressed to one of this node's segments that it would not act on.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_segments_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_segments_dropped_total %d\n", segments.Dropped)
	fmt.Fprint(w, "# HELP ranet_lite_segments_answered_total ICMP errors sent for refused packets, which is the half of the dropped ones whose sender was told why.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_segments_answered_total counter\n")
	fmt.Fprintf(w, "ranet_lite_segments_answered_total %d\n", segments.Answered)
	fmt.Fprint(w, "# HELP ranet_lite_steered_total This node's own packets a steering policy encapsulated.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_steered_total counter\n")
	fmt.Fprintf(w, "ranet_lite_steered_total %d\n", segments.Steered)
	fmt.Fprint(w, "# HELP ranet_lite_steer_dropped_total Packets a steering policy claimed and this node did not send: too large to encapsulate, or with no route to their first segment.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_steer_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_steer_dropped_total{reason=\"too_large\"} %d\n", segments.Unsteered)
	fmt.Fprintf(w, "ranet_lite_steer_dropped_total{reason=\"no_route\"} %d\n", segments.Unrouted)
}

// renderKernel writes the route reconciler's last pass, the half of a node
// that bird_protocol_* reported for kbabel4 and kbabel6 while BIRD still ran
// here. A node whose reconciler is off writes none of it, rather than four
// zeroes that read as a reconciler doing nothing.
func (c *Client) renderKernel(w io.Writer) {
	kernel := c.kernel()
	if !kernel.Enabled {
		return
	}
	fmt.Fprint(w, "# HELP ranet_lite_kernel_routes_installed Routes the kernel holds for this reconciler as of its last pass.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_kernel_routes_installed gauge\n")
	fmt.Fprintf(w, "ranet_lite_kernel_routes_installed %d\n", kernel.Installed)
	fmt.Fprint(w, "# HELP ranet_lite_kernel_routes_skipped Routes the mesh selected that the last pass did not install: one the platform cannot represent, or one whose key another writer holds.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_kernel_routes_skipped gauge\n")
	fmt.Fprintf(w, "ranet_lite_kernel_routes_skipped %d\n", kernel.Skipped)
	fmt.Fprint(w, "# HELP ranet_lite_kernel_pass_timestamp_seconds When the last pass finished, and zero before the first one has.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_kernel_pass_timestamp_seconds gauge\n")
	fmt.Fprintf(w, "ranet_lite_kernel_pass_timestamp_seconds %d\n", unixOrZero(kernel.PassAt))
	fmt.Fprint(w, "# HELP ranet_lite_kernel_pass_failed Whether the last pass reported an error.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_kernel_pass_failed gauge\n")
	fmt.Fprintf(w, "ranet_lite_kernel_pass_failed %d\n", boolValue(kernel.Err != ""))
}

// unixOrZero is the unix time of a pass, and zero rather than a negative
// number before the first one, since the zero time predates the epoch by two
// millennia and an alert reading "older than five minutes" would be true of it
// either way.
func unixOrZero(at time.Time) int64 {
	if at.IsZero() {
		return 0
	}
	return at.Unix()
}

// renderReceiveCounters writes the three the hub keeps. They are separate
// series on purpose: a rising dropped means this node is behind on receive,
// which is the only signal there is for that; a rising refused means somebody
// is sending it datagrams it has nowhere to put; and keepalives are the RFC
// 3948 section 2.3 datagrams a NATed peer sends to hold its mapping open,
// which are expected rather than unwanted. Anyone who can reach the port can
// raise any of them, so none is a fault by itself, and mixing them would make
// the first two unreadable.
func (c *Client) renderReceiveCounters(w io.Writer) {
	fmt.Fprint(w, "# HELP ranet_lite_receive_dropped_total Inbound datagrams a full receive queue refused.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_receive_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_receive_dropped_total %d\n", c.hubDropped())

	fmt.Fprint(w, "# HELP ranet_lite_receive_refused_total Inbound datagrams nothing here wanted: naming no SPI this node holds, too short or empty, for a full unclaimed queue, or with an unreadable control message or source.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_receive_refused_total counter\n")
	fmt.Fprintf(w, "ranet_lite_receive_refused_total %d\n", c.hubRefused())

	fmt.Fprint(w, "# HELP ranet_lite_receive_keepalives_total Inbound RFC 3948 NAT keepalives, ignored on arrival.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_receive_keepalives_total counter\n")
	fmt.Fprintf(w, "ranet_lite_receive_keepalives_total %d\n", c.hubKeepalives())
}

// hubDropped and hubRefused are zero before the hub exists, which is every
// call from a test that builds a Client by hand.
func (c *Client) hubDropped() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Dropped()
}

func (c *Client) hubRefused() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Refused()
}

func (c *Client) hubKeepalives() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Keepalives()
}

// MetricsHandler serves Metrics, for mounting next to the pprof endpoint.
func (c *Client) MetricsHandler() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		c.Metrics(w)
	})
}

// label escapes a label value the way the Prometheus text exposition format
// defines it, which is three sequences and no others: a backslash, a double
// quote and a newline. Go's %q escapes every rune unicode.IsPrint rejects, as
// \t or \u00a0, and a scrape carrying one of those is refused whole rather
// than in part, so one tab or non-breaking space pasted into an organization
// or common name takes every series on the node out of monitoring. The values
// here are built from those names and from the identity a peer asserts.
func label(value string) string {
	var b strings.Builder
	for _, r := range value {
		switch r {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		case '\n':
			b.WriteString(`\n`)
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

func boolValue(b bool) int {
	if b {
		return 1
	}
	return 0
}

// paths is every path holding a live session, sorted so a scrape is stable.
func (s *sessionSet) paths() []string {
	s.mu.Lock()
	paths := make([]string, 0, len(s.live))
	for path := range s.live {
		paths = append(paths, path)
	}
	s.mu.Unlock()
	slices.Sort(paths)
	return paths
}

// countInbound is called once per decrypted batch rather than once per packet,
// so the hot path pays one atomic add per batch and nothing per packet. The
// refused half is noteInboundDropped's, which counts and reports together: two
// callers adding to one counter is how a batch gets counted twice.
func (c *Client) countInbound(delivered int) {
	if delivered > 0 {
		c.inboundPackets.Add(uint64(delivered))
	}
}

// espDropReportInterval bounds how often refused ESP packets are said out
// loud. The counter behind it is exact, and an operator reads that; the log
// line only has to point at it.
const espDropReportInterval = 10 * time.Second

// noteInboundDropped reports ESP packets that did not survive decryption or
// validation, at most once an interval.
//
// The inbound SPI is cleartext in every datagram, so anyone who has seen one
// can send datagrams that are refused at the replay check, before any crypto,
// and a line per batch is a line per datagram. That write is synchronous, on
// the one goroutine that also hands babel its packets, and it takes the
// process-wide log mutex that babel, IKE and the kernel reconciler share:
// measured at 248,000 spoofed datagrams in one second drawing 156,000 lines
// and 24 MB of stderr for 15 MB on the wire, and withdrawing the mesh's route
// to this node in under four seconds. Hub.noteDrop and installRoute are the
// same limiter for the same reason.
func (c *Client) noteInboundDropped(peer string, count int, last error) {
	total := c.inboundDropped.Add(uint64(count))
	now := int64(time.Since(c.started))
	previous := c.dropReported.Load()
	if now-previous < int64(espDropReportInterval) || !c.dropReported.CompareAndSwap(previous, now) {
		return
	}
	slog.Warn("esp inbound packets dropped", "peer", peer, "dropped_total", total, "err", last)
}
