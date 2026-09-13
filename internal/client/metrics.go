package client

import (
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
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

	fmt.Fprint(w, "# HELP ranet_lite_esp_inbound_packets_total Decrypted ESP packets delivered.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_esp_inbound_packets_total counter\n")
	fmt.Fprintf(w, "ranet_lite_esp_inbound_packets_total %d\n", c.inboundPackets.Load())
	fmt.Fprint(w, "# HELP ranet_lite_esp_inbound_dropped_total ESP packets that failed to decrypt or validate.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_esp_inbound_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_esp_inbound_dropped_total %d\n", c.inboundDropped.Load())

	// The inbound counterpart of ranet_lite_peer_send_dropped_total, and the
	// only signal that this node is behind on receive rather than losing
	// packets on the wire. Anyone who can reach the port can raise it, so a
	// rising count is not by itself a fault.
	fmt.Fprint(w, "# HELP ranet_lite_receive_dropped_total Inbound datagrams a full receive queue refused.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_receive_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_receive_dropped_total %d\n", c.hubDropped())
}

// hubDropped is zero before the hub exists, which is every call from a test
// that builds a Client by hand.
func (c *Client) hubDropped() uint64 {
	if c.hub == nil {
		return 0
	}
	return c.hub.Dropped()
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
// so the hot path pays two atomic adds per batch and nothing per packet.
func (c *Client) countInbound(delivered, dropped int) {
	if delivered > 0 {
		c.inboundPackets.Add(uint64(delivered))
	}
	if dropped > 0 {
		c.inboundDropped.Add(uint64(dropped))
	}
}
