package control

import (
	"net/netip"
	"strings"
	"testing"
	"time"
)

// The column set is the promise the subcommands make, so a rename is a change
// an operator's scripts see and belongs in a diff that says so.
func TestRenderersKeepTheirColumns(t *testing.T) {
	for name, test := range map[string]struct {
		render func(*strings.Builder)
		want   []string
	}{
		"neighbors": {
			render: func(b *strings.Builder) { RenderNeighbors(b, nil) },
			want:   []string{"peer", "state", "cost", "rxcost", "rtt", "routes", "expires", "dropped", "failed"},
		},
		"routes": {
			render: func(b *strings.Builder) { RenderRoutes(b, nil) },
			want:   []string{"destination", "from", "via", "metric", "router-id", "seqno", "paths"},
		},
		"sessions": {
			render: func(b *strings.Builder) { RenderSessions(b, nil) },
			want:   []string{"path", "peer", "remote", "end", "state", "spi in/out", "age", "idle"},
		},
		"peers": {
			render: func(b *strings.Builder) { RenderPeers(b, nil) },
			want:   []string{"path", "peer", "serial", "from", "state"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			var out strings.Builder
			test.render(&out)
			header := strings.Fields(out.String())
			for _, column := range test.want {
				if !strings.Contains(out.String(), column) {
					t.Errorf("the %s header is %q, want it to carry %q", name, header, column)
				}
			}
		})
	}
}

// 65535 is infinity and a reader should not have to remember that. An absent
// measurement prints as a dash rather than as a zero, because zero is a cost a
// link can have and a round trip a loopback peer measures.
func TestNeighborsSpellInfinityAndAbsence(t *testing.T) {
	var out strings.Builder
	RenderNeighbors(&out, []Neighbor{{Peer: "example/gateway@0", Cost: 65535}})
	line := out.String()
	if !strings.Contains(line, "inf") {
		t.Errorf("an infinite cost printed as %q", line)
	}
	if strings.Count(line, "-") < 2 {
		t.Errorf("an unmeasured rxcost and rtt printed as %q, want dashes", line)
	}

	cost := uint16(96)
	rtt := Duration(27200 * time.Microsecond)
	out.Reset()
	RenderNeighbors(&out, []Neighbor{{Peer: "example/gateway@0", Alive: true, Cost: 116, ReportedCost: &cost, RTT: &rtt}})
	for _, want := range []string{"up", "116", "96", "27.2ms"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("a measured neighbor printed as %q, want it to carry %q", out.String(), want)
		}
	}
}

// A prefix this node originates and one held unreachable are the two rows an
// operator is usually looking for, and neither has a next hop to print.
func TestRoutesNameOriginatedAndUnreachable(t *testing.T) {
	var out strings.Builder
	RenderRoutes(&out, []Route{
		{Destination: netip.MustParsePrefix("2001:db8::/48"), Originated: true},
		{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Metric: 65535},
		{Destination: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/32"), Via: "example/exit@0", Metric: 212},
	})
	for _, want := range []string{"this node", "unreachable", "2001:db8::/32", "example/exit@0"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the route table printed as %q, want it to carry %q", out.String(), want)
		}
	}
}

// The role line is the three settings that decide what a node is on a fleet,
// said as words rather than as booleans a reader reassembles.
func TestStatusSaysTheRoleInWords(t *testing.T) {
	var out strings.Builder
	RenderStatus(&out, Status{Organization: "example", CommonName: "laptop", Responder: false, FullMesh: true, NoTransit: true})
	for _, want := range []string{"example/laptop", "initiator", "full mesh", "no transit", "off, routes configured externally"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status printed as %q, want it to carry %q", out.String(), want)
		}
	}
	if strings.Contains(out.String(), "responder") {
		t.Error("a node with responder off is reported as one")
	}
}

// Go's own String gives "1h3m0.5762s" for an uptime, where the digits make two
// rows harder to compare and carry nothing.
func TestShortDurationRoundsToWhatIsReadable(t *testing.T) {
	for _, test := range []struct {
		in   time.Duration
		want string
	}{
		{27234 * time.Microsecond, "27.2ms"},
		{9*time.Second + 470*time.Millisecond, "9.5s"},
		{time.Minute + 30*time.Second + 400*time.Millisecond, "1m30s"},
		{time.Hour + 3*time.Minute + 576*time.Millisecond, "1h3m0s"},
		{-time.Second, "-"},
	} {
		if got := shortDuration(test.in); got != test.want {
			t.Errorf("shortDuration(%s) = %s, want %s", test.in, got, test.want)
		}
	}
}

// The kernel line names the VRF the mesh is in, and says when a socket
// outside it will not be matched by a reply that arrived through it. Only
// then: on a node whose host is set up for it the line would otherwise carry
// a clause that is true of every fleet node and tells a reader nothing.
func TestKernelLineNamesAVRFAndWhatItIsMissing(t *testing.T) {
	on, off := true, false
	for name, test := range map[string]struct {
		status   KernelStatus
		want     string
		unwanted string
	}{
		"no vrf":        {status: KernelStatus{Enabled: true, Where: "table 200 protocol 155"}, want: "table 200 protocol 155", unwanted: "vrf"},
		"vrf, accepted": {status: KernelStatus{Enabled: true, VRF: "mesh", L3mdevAccept: &on}, want: "vrf mesh", unwanted: "l3mdev"},
		"vrf, refused":  {status: KernelStatus{Enabled: true, VRF: "mesh", L3mdevAccept: &off}, want: "vrf mesh without l3mdev accept"},
	} {
		t.Run(name, func(t *testing.T) {
			line := kernelLine(test.status)
			if !strings.Contains(line, test.want) {
				t.Errorf("the kernel line reads %q, want it to carry %q", line, test.want)
			}
			if test.unwanted != "" && strings.Contains(line, test.unwanted) {
				t.Errorf("the kernel line reads %q, want it not to mention %q", line, test.unwanted)
			}
		})
	}
}
