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
	hub, err := transport.NewHub("127.0.0.1:0")
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
