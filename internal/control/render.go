package control

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
	"time"
)

// The renderers below are the default output of the subcommands, with -json
// giving the wire form instead. They are here rather than in the command so
// that a test can hold the columns still: the column set is the promise the
// subcommands make, and a rename of one is a change an operator's scripts see.

// table writes rows under a header, aligned. Every renderer goes through it so
// the whole command speaks in one shape.
func table(w io.Writer, header []string, rows [][]string) {
	out := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(out, strings.Join(header, "\t"))
	for _, row := range rows {
		fmt.Fprintln(out, strings.Join(row, "\t"))
	}
	out.Flush()
}

// RenderStatus writes the node's own summary as aligned name and value pairs,
// which reads better than a one-row table for a record with this many fields.
func RenderStatus(w io.Writer, s Status) {
	rows := [][]string{
		{"node", s.Organization + "/" + s.CommonName},
		{"version", s.Version},
		{"uptime", shortDuration(time.Duration(s.Uptime))},
		{"port", fmt.Sprint(s.Port)},
		{"endpoints", strings.Join(s.Endpoints, " ")},
		{"tun", fmt.Sprintf("%s mtu %d queues %d", s.TUN, s.MTU, s.Queues)},
		{"role", role(s)},
		{"forwarding", fmt.Sprintf("ipv4 %s ipv6 %s", onOff(s.ForwardsIPv4), onOff(s.ForwardsIPv6))},
		{"registry", fmt.Sprintf("%s, %d nodes in %d organizations", s.Registry.Path, s.Registry.Nodes, s.Registry.Organizations)},
		{"kernel", kernelLine(s.Kernel)},
		{"dialers", fmt.Sprintf("%d running", s.Counts.Dialers)},
		{"sessions", fmt.Sprint(s.Counts.Sessions)},
		{"neighbors", fmt.Sprintf("%d, %d alive", s.Counts.Neighbors, s.Counts.NeighborsAlive)},
		{"routes", fmt.Sprintf("%d prefixes, %d selected, %d originated", s.Counts.Prefixes, s.Counts.Selected, s.Counts.Originated)},
		{"originate", originateLine(s.Originate)},
		{"segments", segmentLine(s)},
		{"esp", fmt.Sprintf("%d in, %d dropped, %d refused", s.ESP.InboundPackets, s.ESP.InboundDropped, s.ESP.ReceiveRefused)},
	}
	out := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	for _, row := range rows {
		fmt.Fprintf(out, "%s\t%s\n", row[0], row[1])
	}
	out.Flush()
}

// role is the three settings that decide what this node is on a fleet, said as
// words rather than as three booleans an operator has to reassemble.
func role(s Status) string {
	parts := []string{"initiator"}
	if s.Responder {
		parts = append(parts, "responder")
	}
	if s.FullMesh {
		parts = append(parts, "full mesh")
	}
	if s.NoTransit {
		parts = append(parts, "no transit")
	} else {
		parts = append(parts, "transit")
	}
	return strings.Join(parts, ", ")
}

func kernelLine(k KernelStatus) string {
	if !k.Enabled {
		return "off, routes configured externally"
	}
	line := fmt.Sprintf("%s, %d installed", k.Where, k.Installed)
	if k.Skipped > 0 {
		line += fmt.Sprintf(", %d skipped", k.Skipped)
	}
	if k.PassAt.IsZero() {
		line += ", no pass yet"
	} else {
		line += fmt.Sprintf(", last pass %s ago", shortDuration(time.Since(k.PassAt)))
	}
	if k.Err != "" {
		line += ", " + k.Err
	}
	return line
}

// segmentLine says nothing but "off" on a node that configures no segment
// routing, which is most of them, rather than three zeroes an operator has to
// read as an absence.
func segmentLine(s Status) string {
	if len(s.Segments) == 0 {
		return "off"
	}
	return fmt.Sprintf("%s (%d forwarded, %d delivered, %d dropped)",
		strings.Join(s.Segments, ", "),
		s.SegmentCounters.Forwarded, s.SegmentCounters.Delivered, s.SegmentCounters.Dropped)
}

func originateLine(routes []Originated) string {
	if len(routes) == 0 {
		return "none"
	}
	text := make([]string, 0, len(routes))
	for _, route := range routes {
		text = append(text, route.String())
	}
	return strings.Join(text, " ")
}

// RenderNeighbors writes the columns `birdc show babel neighbors` writes, plus
// the reverse cost and the two dataplane counters BIRD does not have.
func RenderNeighbors(w io.Writer, neighbors []Neighbor) {
	rows := make([][]string, 0, len(neighbors))
	for _, n := range neighbors {
		rows = append(rows, []string{
			n.Peer,
			upDown(n.Alive),
			cost(n.Cost),
			optionalCost(n.ReportedCost),
			optionalDuration(n.RTT),
			fmt.Sprint(n.Routes),
			shortDuration(time.Duration(n.Expires)),
			fmt.Sprint(n.Dropped),
			fmt.Sprint(n.SendFailed),
		})
	}
	table(w, []string{"peer", "state", "cost", "rxcost", "rtt", "routes", "expires", "dropped", "failed"}, rows)
}

// RenderRoutes writes the mesh route table, one line per prefix, which is the
// answer `birdc show route` gave while Babel lived in BIRD.
func RenderRoutes(w io.Writer, routes []Route) {
	rows := make([][]string, 0, len(routes))
	for _, r := range routes {
		from := ""
		if r.From.IsValid() {
			from = r.From.String()
		}
		via := r.Via
		if via == "" {
			via = "unreachable"
		}
		if r.Originated {
			via = "this node"
		}
		rows = append(rows, []string{
			r.Destination.String(),
			from,
			via,
			cost(r.Metric),
			r.RouterID,
			fmt.Sprint(r.Seqno),
			fmt.Sprint(r.Candidates),
		})
	}
	table(w, []string{"destination", "from", "via", "metric", "router-id", "seqno", "paths"}, rows)
}

// RenderSessions writes the live IKE SAs, which `swanctl --list-sas` answered
// while strongSwan carried them.
func RenderSessions(w io.Writer, sessions []Session) {
	rows := make([][]string, 0, len(sessions))
	for _, s := range sessions {
		rows = append(rows, []string{
			s.Path,
			s.Peer,
			s.Remote,
			end(s.Preferred),
			upDown(s.Active),
			fmt.Sprintf("%08x/%08x", s.LocalSPI, s.RemoteSPI),
			shortDuration(time.Duration(s.Age)),
			shortDuration(time.Duration(s.Idle)),
		})
	}
	table(w, []string{"path", "peer", "remote", "end", "state", "spi in/out", "age", "idle"}, rows)
}

// RenderPeers writes what this node dials and whether it got there, which is
// the question a peers list in a config file cannot answer on its own.
func RenderPeers(w io.Writer, peers []Peer) {
	rows := make([][]string, 0, len(peers))
	for _, p := range peers {
		serial := p.SerialNumber
		if serial == "" {
			serial = "any"
		}
		rows = append(rows, []string{
			p.Path,
			p.Organization + "/" + p.CommonName,
			serial,
			source(p.Generated),
			upDown(p.Connected),
		})
	}
	table(w, []string{"path", "peer", "serial", "from", "state"}, rows)
}

func upDown(up bool) string {
	if up {
		return "up"
	}
	return "down"
}

func onOff(on bool) string {
	if on {
		return "on"
	}
	return "off"
}

func end(preferred bool) string {
	if preferred {
		return "initiator"
	}
	return "responder"
}

func source(generated bool) string {
	if generated {
		return "registry"
	}
	return "config"
}

// cost spells the infinite metric rather than printing 65535, which is a
// number an operator has to remember the meaning of.
func cost(metric uint16) string {
	if metric == 65535 {
		return "inf"
	}
	return fmt.Sprint(metric)
}

func optionalCost(metric *uint16) string {
	if metric == nil {
		return "-"
	}
	return cost(*metric)
}

func optionalDuration(d *Duration) string {
	if d == nil {
		return "-"
	}
	return shortDuration(time.Duration(*d))
}

// shortDuration rounds to something a person reads at a glance. Go's own
// String gives "1h3m0.5762s" for an uptime, where the seconds carry no
// information and the digits make two rows harder to compare.
func shortDuration(d time.Duration) string {
	switch {
	case d < 0:
		return "-"
	case d < time.Second:
		return d.Round(100 * time.Microsecond).String()
	case d < time.Minute:
		return d.Round(100 * time.Millisecond).String()
	case d < time.Hour:
		return d.Round(time.Second).String()
	default:
		return d.Round(time.Minute).String()
	}
}
