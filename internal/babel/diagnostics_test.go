package babel

import (
	"net/netip"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// adoptOriginatedLocked deletes an originated prefix's route table entry, so a
// dump that walks the route table alone omits every prefix this node
// announces, which is the half an operator checks first.
func TestRouteDumpCarriesOriginatedPrefixes(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, Routes{}, Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	own := netip.MustParsePrefix("198.18.104.117/32")
	exit := netip.MustParsePrefix("::/0")
	from := netip.MustParsePrefix("3fff:a::/36")
	speaker.OriginateFrom(own, netip.Prefix{})
	speaker.OriginateFrom(exit, from)

	dump := speaker.RouteDump()
	if len(dump) != 2 {
		t.Fatalf("the dump holds %d routes, want the two this node originates: %+v", len(dump), dump)
	}
	byDestination := make(map[netip.Prefix]RouteStat, len(dump))
	for _, route := range dump {
		byDestination[route.Destination] = route
	}
	plain, ok := byDestination[own]
	if !ok {
		t.Fatalf("the dump omits %s: %+v", own, dump)
	}
	if !plain.Originated || plain.Metric != 0 || plain.Via != "" {
		t.Errorf("an originated prefix reads as %+v, want originated at metric 0 with no next hop", plain)
	}
	sourceSpecific, ok := byDestination[exit]
	if !ok {
		t.Fatalf("the dump omits %s: %+v", exit, dump)
	}
	if sourceSpecific.Source != from {
		t.Errorf("a source-specific announcement lost its source: %+v", sourceSpecific)
	}
	if stats := speaker.Stats(); stats.Prefixes != 2 || stats.Originated != 2 {
		t.Errorf("stats count %d prefixes and %d originated, want two of each", stats.Prefixes, stats.Originated)
	}
}

// A learned prefix reports the route that was selected, and one every neighbor
// has retracted stays in the dump as a hold, which is the row that explains a
// destination the mesh can no longer reach.
func TestRouteDumpReportsSelectionAndHolds(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, Routes{}, Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("example/gateway@0", nil, nil)
	handle := speaker.AddPeer(peer)
	defer handle.Close()
	neighbor := speaker.neighbors[peer.ID]
	makeNeighborReachable(neighbor)
	dest := netip.MustParsePrefix("3fff:1:69c:98d0::/60")
	key := routeKey{dest: dest}
	speaker.routes.update(neighbor, key, advertisement{routerID: [8]byte{1, 2}, seqno: 7, metric: 100}, time.Minute, time.Now())

	dump := speaker.RouteDump()
	if len(dump) != 1 {
		t.Fatalf("the dump holds %d routes, want one: %+v", len(dump), dump)
	}
	if dump[0].Via != peer.ID {
		t.Fatalf("a selected route reads as %+v, want it via %s", dump[0], peer.ID)
	}
	if dump[0].Seqno != 7 || dump[0].Candidates != 1 {
		t.Errorf("a selected route reads as %+v, want seqno 7 from one candidate", dump[0])
	}
	if dump[0].RouterID != [8]byte{1, 2} {
		t.Errorf("a selected route lost its origin: %+v", dump[0])
	}
}

// Cost is this node's view of a link and ReportedCost is the neighbor's, so a
// link that carries one way can be told from one that carries neither. Both
// have a "not measured" state that zero cannot express.
func TestNeighborStatsCarryBothDirections(t *testing.T) {
	mesh := &netstack.Mesh{Routes: netstack.NewRouteTable()}
	speaker, err := New(Config{}, Routes{}, Runtime{}, mesh)
	if err != nil {
		t.Fatal(err)
	}
	peer := netstack.NewPeer("example/gateway@0", nil, nil)
	handle := speaker.AddPeer(peer)
	defer handle.Close()

	fresh := speaker.Stats()
	if len(fresh.Neighbors) != 1 {
		t.Fatalf("stats hold %d neighbors, want one", len(fresh.Neighbors))
	}
	if fresh.Neighbors[0].HaveReportedCost || fresh.Neighbors[0].HaveRTT {
		t.Errorf("a neighbor that has sent no IHU reads as %+v, want neither measurement", fresh.Neighbors[0])
	}
	if fresh.Neighbors[0].Expires != 0 {
		t.Errorf("a neighbor with no Hello deadline expires in %s, want zero rather than a negative", fresh.Neighbors[0].Expires)
	}

	neighbor := speaker.neighbors[peer.ID]
	speaker.mu.Lock()
	makeNeighborReachable(neighbor)
	neighbor.measuredRTT, neighbor.haveRTT = 27*time.Millisecond, true
	speaker.mu.Unlock()

	measured := speaker.Stats()
	if !measured.Neighbors[0].HaveReportedCost || !measured.Neighbors[0].HaveRTT {
		t.Fatalf("a measured neighbor reads as %+v", measured.Neighbors[0])
	}
	if measured.Neighbors[0].RTT != 27*time.Millisecond {
		t.Errorf("the round trip reads as %s", measured.Neighbors[0].RTT)
	}
	if measured.Neighbors[0].Expires <= 0 {
		t.Errorf("a live neighbor expires in %s, want a deadline ahead of now", measured.Neighbors[0].Expires)
	}
}
