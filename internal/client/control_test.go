package client

import (
	"net/netip"
	"testing"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/control"
	"github.com/NickCao/ranet-lite/internal/egress"
	"github.com/NickCao/ranet-lite/internal/netstack"
)

// A field added to the dataplane's counters and not to the wire's is a number
// that silently stops being reported, as an earlier version of the mapper in
// control.go allowed. The conversion below is legal only while the two
// structs have identical underlying types, so it is the check writing the
// fields out by name cannot give.
func TestSegmentCountersDoNotDrift(t *testing.T) {
	var counters netstack.SegmentCounters
	_ = control.SegmentCounters(counters)
}

// A SID this node also carries as an address would swallow every ordinary
// packet to that address: the inbound seam acts on the destination before the
// tun sees it, and a packet with no routing header is then refused rather than
// delivered. On linux the two coexist, because there the SID is a route.
func TestLocalSegmentOnOneOfThisNodesAddressesIsRefused(t *testing.T) {
	cfg := &config.Config{
		Kernel:   config.Kernel{Addresses: []string{"3fff:1:69c:8c6::1/128"}},
		Segments: config.Segments{Local: []config.LocalSegment{{SID: "3fff:1:69c:8c6::1", Behavior: "End.DT46"}}},
	}
	if _, err := localSegments(cfg); err == nil {
		t.Error("a segment on one of this node's own addresses was accepted")
	}
	cfg.Kernel.Addresses = []string{"3fff:1:69c:8c6::9/128"}
	if _, err := localSegments(cfg); err != nil {
		t.Errorf("a segment beside an unrelated address was refused: %v", err)
	}

	// assign_originated puts every originated prefix on the device too, so the
	// check covers everything the reconciler assigns rather than the addresses
	// list alone.
	cfg.Kernel.AssignOriginated = true
	cfg.Originate = []string{"3fff:1:69c:8c6::1/128"}
	if _, err := localSegments(cfg); err == nil {
		t.Error("a segment on a prefix this node assigns from originate was accepted")
	}
}

// A host address written with a prefix length is refused rather than masked,
// as the rule list refuses the same typo. Masking steers a whole prefix where
// one address was meant and says nothing about it.
func TestSteerSelectorWithHostBitsIsRefused(t *testing.T) {
	cfg := &config.Config{Segments: config.Segments{
		Source: "3fff:1:69c:8c0::1",
		Steer:  []config.SteerEntry{{From: "3fff:a::198:18:104:117/64", Via: []string{"3fff:1:69c:98d6::1"}}},
	}}
	if _, err := steerTable(cfg); err == nil {
		t.Error("a selector with bits below its prefix length was accepted")
	}
	cfg.Segments.Steer[0].From = "3fff:a::198:18:104:117/128"
	if _, err := steerTable(cfg); err != nil {
		t.Errorf("a host selector was refused: %v", err)
	}
}

// An exit withholds a prefix whose translation rule is not installed, so that
// this node stops attracting traffic it would have to drop. A second,
// unconditional announcement of the same prefix takes that back and leaves the
// withholding reporting as working while changing nothing on the wire.
func TestEgressPrefixAnnouncedUnconditionallyIsRefused(t *testing.T) {
	exit := netip.MustParsePrefix("198.51.100.0/24")
	cfg := &config.Config{
		Originate: []string{"198.51.100.0/24"},
		Egress:    egress.Config{Enable: true, Advertise: []netip.Prefix{exit}},
	}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err == nil {
		t.Error("a prefix announced both by the capability and unconditionally was accepted")
	}
	cfg.Originate = []string{"10.88.0.2/32"}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err != nil {
		t.Errorf("an unrelated announcement was refused: %v", err)
	}

	// babel.originate is the other half of the same list, so it has to be
	// covered too: the source-specific spelling of an exit's own default is
	// written there and nowhere else.
	cfg.Babel.Originate = []config.OriginatePrefix{{Prefix: exit}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err == nil {
		t.Error("a prefix announced through babel.originate as well was accepted")
	}
}

// The capability announces nothing until the translator says it may, so a node
// whose command never built one announces exactly the configured list.
func TestOriginatedSetTakesTheEgressPrefixesFromTheTranslator(t *testing.T) {
	cfg := &config.Config{Originate: []string{"10.88.0.2/32"}}
	c := &Client{}
	routes, err := c.originated(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 1 {
		t.Fatalf("announced %v with no translator, want the configured list alone", routes)
	}
	exit := netip.MustParsePrefix("0.0.0.0/0")
	c.SetEgressAnnounce(func() []netip.Prefix { return []netip.Prefix{exit} })
	routes, err = c.originated(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(routes) != 2 || routes[1].Destination != exit {
		t.Errorf("announced %v, want the configured list and the exit's own prefix", routes)
	}
}
