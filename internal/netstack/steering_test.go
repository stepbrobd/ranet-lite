package netstack

import (
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/srv6"
	"golang.zx2c4.com/wireguard/tun"
)

// Steering happens before the route lookup, so a steered packet goes to the
// peer its first segment selects rather than to the one its own destination
// would have selected. Calling steer directly cannot see that: the seam has to
// re-read the addresses off the encapsulated packet, and dropping that leaves
// the packet correctly encapsulated and handed to the wrong peer, which
// arrives at a node holding no such segment.
func TestOutboundSeamRoutesBySegmentRatherThanByDestination(t *testing.T) {
	exit := segAddr("2a0c:b641:69c:98d6::1")
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From:   segPrefix("2602:f590::17/128"),
		Policy: srv6.Policy{Source: segAddr("2a0c:b641:69c:8c0::1"), Path: []netip.Addr{exit}},
	}})
	if err != nil {
		t.Fatal(err)
	}

	viaSegment := make(chan []byte, 1)
	viaDestination := make(chan []byte, 1)
	segmentPeer := sealingPeer(t, "segment", viaSegment)
	destinationPeer := sealingPeer(t, "destination", viaDestination)

	dev := &utunDevice{
		recordingDevice: recordingDevice{writes: make(chan recordedWrite, 1), events: make(chan tun.Event)},
		reads:           make(chan []byte, 1),
	}
	m := &Mesh{
		Routes:             NewRouteTable(),
		devs:               []tun.Device{dev},
		closed:             make(chan struct{}),
		outboundJobs:       make(chan *outboundBatch, 1),
		outboundFree:       make(chan *outboundBatch, 1),
		outboundBufferSize: tunOffset + outboundPacketBufferSize,
	}
	m.SetSteering(table)
	// The two halves of the mesh: the segment goes one way, the address the
	// packet was written to goes the other.
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("2a0c:b641:69c:98d6::1/128"), segmentPeer)
	m.Routes.Set(netip.Prefix{}, netip.MustParsePrefix("2001:4860:4860::8888/128"), destinationPeer)
	m.outboundFree <- m.newOutboundBatch(1)
	m.startOutboundPipeline()
	defer func() {
		close(m.closed)
		close(dev.reads)
		close(m.outboundJobs)
		m.outboundWorkerWG.Wait()
	}()

	dev.reads <- plainV6(segAddr("2602:f590::17"), segAddr("2001:4860:4860::8888"), "payload")
	select {
	case sent := <-viaSegment:
		if got := netip.AddrFrom16([16]byte(sent[24:40])); got != exit {
			t.Errorf("the peer was handed a packet addressed to %s", got)
		}
	case <-viaDestination:
		t.Fatal("a steered packet went to the peer its inner destination selects")
	case <-time.After(5 * time.Second):
		t.Fatal("nothing was sent")
	}
}

// A steered packet whose first segment the mesh cannot reach is gone at the
// route lookup. Without a counter there the steered figure climbs while the
// traffic disappears and nothing anywhere says so.
func TestSteeredPacketWithNoRouteIsCounted(t *testing.T) {
	table, err := srv6.NewSteerTable([]srv6.Steer{{
		From:   segPrefix("2602:f590::17/128"),
		Policy: srv6.Policy{Source: segAddr("2a0c:b641:69c:8c0::1"), Path: []netip.Addr{segAddr("2a0c:b641:69c:98d6::1")}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	dev := &utunDevice{
		recordingDevice: recordingDevice{writes: make(chan recordedWrite, 1), events: make(chan tun.Event)},
		reads:           make(chan []byte, 1),
	}
	m := &Mesh{
		Routes:             NewRouteTable(),
		devs:               []tun.Device{dev},
		closed:             make(chan struct{}),
		outboundJobs:       make(chan *outboundBatch, 1),
		outboundFree:       make(chan *outboundBatch, 1),
		outboundBufferSize: tunOffset + outboundPacketBufferSize,
	}
	m.startSegmentReports()
	m.SetSteering(table)
	m.outboundFree <- m.newOutboundBatch(1)
	m.startOutboundPipeline()
	defer func() {
		close(m.closed)
		close(dev.reads)
		close(m.outboundJobs)
		m.outboundWorkerWG.Wait()
	}()

	dev.reads <- plainV6(segAddr("2602:f590::17"), segAddr("2001:4860:4860::8888"), "payload")
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if counters := m.SegmentCounters(); counters.Dropped > 0 {
			if counters.Steered != 1 {
				t.Errorf("the packet was counted steered %d times", counters.Steered)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("a steered packet with nowhere to go was not counted: %+v", m.SegmentCounters())
}

// sealingPeer records what a peer was handed, so a test can tell which peer a
// packet went to rather than only that it left.
func sealingPeer(t *testing.T, id string, seen chan []byte) *Peer {
	t.Helper()
	peer := NewPeerReserved(id, func(int) (BatchSealer, error) {
		return func(raw [][]byte, _ []byte, out [][]byte) ([][]byte, error) {
			seen <- append([]byte(nil), raw[0]...)
			return out[:0], nil
		}, nil
	}, func([][]byte) error { return nil })
	t.Cleanup(peer.Close)
	return peer
}
