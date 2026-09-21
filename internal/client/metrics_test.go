package client

import (
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/control"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// countingWriter counts writes rather than keeping them, the unit a report
// that must not be one line per packet is measured in.
type countingWriter struct{ n *atomic.Int64 }

func (w countingWriter) Write(b []byte) (int, error) { w.n.Add(1); return len(b), nil }

// The inbound SPI is cleartext in every datagram, so anyone who has seen one
// can send datagrams this node refuses at the replay check, before any crypto.
// A line per refused batch is then a line per datagram, written synchronously
// on the goroutine that also hands babel its packets and under the log mutex
// every other component shares, which is how a flood of small datagrams
// withdraws this node's routes from the mesh rather than merely wasting its
// time. The count has to stay exact; only the saying of it is bounded.
func TestRefusedESPPacketsAreCountedExactlyAndSaidRarely(t *testing.T) {
	var lines atomic.Int64
	previous := slog.Default()
	slog.SetDefault(slog.New(slog.NewTextHandler(countingWriter{&lines}, nil)))
	t.Cleanup(func() { slog.SetDefault(previous) })

	c := &Client{started: time.Now()}
	c.dropReported.Store(-int64(espDropReportInterval))
	const batches = 20000
	for range batches {
		c.noteInboundDropped("peer", 1, errors.New("replayed"))
	}
	if got := c.inboundDropped.Load(); got != batches {
		t.Errorf("the counter reads %d for %d refused packets", got, batches)
	}
	if got := lines.Load(); got != 1 {
		t.Errorf("%d refused batches wrote %d log lines, want the one the interval allows", batches, got)
	}

	// The interval bounds it, not a once-ever flag: an operator has to hear
	// about a flood that is still going.
	c.dropReported.Store(int64(time.Since(c.started)) - int64(espDropReportInterval))
	c.noteInboundDropped("peer", 1, errors.New("replayed"))
	if got := lines.Load(); got != 2 {
		t.Errorf("after the interval passed the report wrote %d lines in total, want 2", got)
	}
}

// A datagram naming no SPI this node holds is refused by the hub, and the
// metric is the only way an operator tells that from silence. It is its own
// series because the queue-full one means something else entirely.
func TestMetricsRendersWhatTheHubRefused(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	sender, err := net.Dial("udp", net.JoinHostPort("127.0.0.1",
		strconv.Itoa(hub.LocalAddr().(*net.UDPAddr).Port)))
	if err != nil {
		t.Fatal(err)
	}
	defer sender.Close()
	// An ESP SPI no Mux holds, which anyone who can reach the port can send
	// and which an operator needs to be able to see.
	if _, err := sender.Write([]byte{9, 9, 9, 9, 0, 0, 0, 1, 0, 0, 0, 0}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for hub.Refused() == 0 {
		if time.Now().After(deadline) {
			t.Fatal("the hub refused nothing, so this proves nothing")
		}
		time.Sleep(5 * time.Millisecond)
	}

	c := &Client{sessions: newSessionSet(), hub: hub}
	var out strings.Builder
	c.renderReceiveCounters(&out)
	for _, want := range []string{
		"# TYPE ranet_lite_receive_refused_total counter",
		fmt.Sprintf("ranet_lite_receive_refused_total %d", hub.Refused()),
		"ranet_lite_receive_dropped_total 0",
	} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, out.String())
		}
	}
}

// The segment routing half and the reconciler are the two subsystems that
// replaced something a scrape used to carry: seg6local routes the kernel
// counted, and the kernel protocols prometheus-bird-exporter read out of
// BIRD. Neither was exported here until a live run went looking for a steered
// path that had stopped working and found the counter only on a socket.
func TestMetricsExposesSegmentsAndTheReconciler(t *testing.T) {
	c := &Client{Mesh: &netstack.Mesh{Routes: netstack.NewRouteTable()}}
	var segments strings.Builder
	c.renderSegmentCounters(&segments)
	for _, want := range []string{
		"# TYPE ranet_lite_segments_forwarded_total counter",
		"ranet_lite_segments_delivered_total 0",
		"ranet_lite_segments_dropped_total 0",
		"ranet_lite_segments_answered_total 0",
		"ranet_lite_steered_total 0",
		// The two ways this node's own steering loses a packet are one series
		// with a reason, since an alert wants their sum and a reader wants
		// which one.
		`ranet_lite_steer_dropped_total{reason="too_large"} 0`,
		`ranet_lite_steer_dropped_total{reason="no_route"} 0`,
	} {
		if !strings.Contains(segments.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, segments.String())
		}
	}

	pass := time.Date(2026, 9, 21, 19, 3, 0, 0, time.UTC)
	c.SetKernelStatus(func() control.KernelStatus {
		return control.KernelStatus{Enabled: true, Installed: 150, Skipped: 8, PassAt: pass, Err: "list routes: bad"}
	})
	var kernel strings.Builder
	c.renderKernel(&kernel)
	for _, want := range []string{
		"ranet_lite_kernel_routes_installed 150",
		"ranet_lite_kernel_routes_skipped 8",
		fmt.Sprintf("ranet_lite_kernel_pass_timestamp_seconds %d", pass.Unix()),
		"ranet_lite_kernel_pass_failed 1",
	} {
		if !strings.Contains(kernel.String(), want) {
			t.Errorf("the scrape does not carry %q:\n%s", want, kernel.String())
		}
	}

	// A node whose reconciler is off writes none of it, rather than four
	// zeroes that read as a reconciler installing nothing.
	c.SetKernelStatus(func() control.KernelStatus { return control.KernelStatus{} })
	var off strings.Builder
	c.renderKernel(&off)
	if off.Len() != 0 {
		t.Errorf("a node with no reconciler wrote %q", off.String())
	}

	// And a reconciler that has not finished a pass reports zero rather than
	// a timestamp two millennia before the epoch.
	c.SetKernelStatus(func() control.KernelStatus { return control.KernelStatus{Enabled: true} })
	var first strings.Builder
	c.renderKernel(&first)
	if !strings.Contains(first.String(), "ranet_lite_kernel_pass_timestamp_seconds 0") {
		t.Errorf("before the first pass the scrape reads:\n%s", first.String())
	}
}

// The kernel line says whether a socket outside the VRF will see a reply,
// because a mesh in a VRF whose host has l3mdev accept off comes up correct
// and carries nothing. The field is filled in here rather than by whoever
// supplies the status, so a caller cannot leave it empty by forgetting.
func TestStatusAnswersL3mdevOnlyWhereThereIsAVRF(t *testing.T) {
	c := &Client{}
	c.SetKernelStatus(func() control.KernelStatus { return control.KernelStatus{Enabled: true, VRF: "mesh"} })
	if got := c.kernel().L3mdevAccept; got == nil {
		t.Error("a node whose mesh is in a vrf does not say whether anything can use it")
	}
	c.SetKernelStatus(func() control.KernelStatus { return control.KernelStatus{Enabled: true} })
	if got := c.kernel().L3mdevAccept; got != nil {
		t.Errorf("a node with no vrf answered a question that does not arise: %v", *got)
	}
}
