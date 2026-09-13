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
	// discards. The name is what a dashboard already references, so the help
	// text is what says so.
	fmt.Fprint(w, "# HELP ranet_lite_esp_inbound_packets_total ESP packets that authenticated and passed validation, including babel control traffic and dummy packets.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_esp_inbound_packets_total counter\n")
	fmt.Fprintf(w, "ranet_lite_esp_inbound_packets_total %d\n", c.inboundPackets.Load())
	fmt.Fprint(w, "# HELP ranet_lite_esp_inbound_dropped_total ESP packets that failed to decrypt or validate.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_esp_inbound_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_esp_inbound_dropped_total %d\n", c.inboundDropped.Load())

	c.renderReceiveCounters(w)
}

// renderReceiveCounters writes the two the hub keeps. They are separate series
// on purpose: a rising dropped means this node is behind on receive, which is
// the only signal there is for that, while a rising refused means somebody is
// sending it datagrams it has nowhere to put. Anyone who can reach the port
// can raise either, so neither is a fault by itself, and mixing them would
// make the first unreadable.
func (c *Client) renderReceiveCounters(w io.Writer) {
	fmt.Fprint(w, "# HELP ranet_lite_receive_dropped_total Inbound datagrams a full receive queue refused.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_receive_dropped_total counter\n")
	fmt.Fprintf(w, "ranet_lite_receive_dropped_total %d\n", c.hubDropped())

	fmt.Fprint(w, "# HELP ranet_lite_receive_refused_total Inbound datagrams naming no SPI this node holds, or too short to name one.\n")
	fmt.Fprint(w, "# TYPE ranet_lite_receive_refused_total counter\n")
	fmt.Fprintf(w, "ranet_lite_receive_refused_total %d\n", c.hubRefused())
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
// loud. The counter behind it is exact and is what an operator reads; the log
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
