package client

import (
	"net/netip"
	"testing"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/control"
	"github.com/NickCao/ranet-lite/internal/egress"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/internal/schema"
	"github.com/NickCao/ranet-lite/internal/srv6"
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
//
// The check spans cap.segment and cap.table, so it lives where the file is
// read rather than in either capability.
func TestLocalSegmentOnOneOfThisNodesAddressesIsRefused(t *testing.T) {
	cfg := &config.Config{
		// A node complete enough to load, since the check under test is the
		// one Validate makes after every capability has passed its own.
		Node: config.Node{Org: "example", Name: "node"},
		Auth: config.Auth{Key: "key.pem", Trust: "trust.json"},
		Link: config.Link{
			Port:      13000,
			Listen:    true,
			Endpoints: []config.Endpoint{{Serial: "0", Family: "ip4"}},
		},
		Cap: config.Caps{
			Table: &kernel.Table{Addresses: []schema.Prefix{schema.MustPrefix("3fff:1:69c:8c6::1/128")}},
			Segment: &srv6.Segments{Local: []srv6.Segment{
				{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEndDT46},
			}},
		},
	}
	if err := cfg.Validate(); err == nil {
		t.Error("a segment on one of this node's own addresses was accepted")
	}
	cfg.Cap.Table.Addresses = []schema.Prefix{schema.MustPrefix("3fff:1:69c:8c6::9/128")}
	if err := cfg.Validate(); err != nil {
		t.Errorf("a segment beside an unrelated address was refused: %v", err)
	}

	// assign_announced puts every announced prefix on the device too, so the
	// check covers everything the reconciler assigns rather than the addresses
	// list alone.
	cfg.Cap.Table.AssignAnnounced = true
	cfg.Cap.Route = &babel.Routes{Announce: announce("3fff:1:69c:8c6::1/128")}
	if err := cfg.Validate(); err == nil {
		t.Error("a segment on a prefix this node assigns from cap.route was accepted")
	}
}

// A host address written with a prefix length is refused rather than masked,
// as the rule list refuses the same typo. Masking steers a whole prefix where
// one address was meant and says nothing about it.
func TestSteerSelectorWithHostBitsIsRefused(t *testing.T) {
	segments := srv6.Segments{
		Source: schema.MustAddr("3fff:1:69c:8c0::1"),
		Steer: []srv6.Steer{{
			From: schema.MustPrefix("3fff:a::198:18:104:117/64"),
			Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
		}},
	}
	if err := segments.Validate(); err == nil {
		t.Error("a selector with bits below its prefix length was accepted")
	}
	segments.Steer[0].From = schema.MustPrefix("3fff:a::198:18:104:117/128")
	if err := segments.Validate(); err != nil {
		t.Errorf("a host selector was refused: %v", err)
	}
}

// An exit withholds a prefix whose translation rule is not installed, so that
// this node stops attracting traffic it would have to drop. A second,
// unconditional announcement of the same prefix takes that back and leaves the
// withholding reporting as working while changing nothing on the wire.
func TestEgressPrefixAnnouncedUnconditionallyIsRefused(t *testing.T) {
	exit := schema.MustPrefix("198.51.100.0/24")
	cfg := &config.Config{Cap: config.Caps{
		Route:  &babel.Routes{Announce: []schema.Announce{{Prefix: exit}}},
		Egress: &egress.Egress{Advertise: []schema.Prefix{exit}},
	}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err == nil {
		t.Error("a prefix announced both by the capability and unconditionally was accepted")
	}
	cfg.Cap.Route.Announce = []schema.Announce{{Prefix: schema.MustPrefix("10.88.0.2/32")}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err != nil {
		t.Errorf("an unrelated announcement was refused: %v", err)
	}

	// The source-specific spelling is the same list, so it is covered too: an
	// exit's own default from its transit prefix is written that way.
	cfg.Cap.Route.Announce = []schema.Announce{{Prefix: exit, From: schema.MustPrefix("2001:db8::/48")}}
	if err := refuseEgressAdvertisedUnconditionally(cfg); err == nil {
		t.Error("a prefix announced with a source as well was accepted")
	}
}

// The capability announces nothing until the translator says it may, so a node
// whose command never built one announces exactly what cap.route names.
func TestAnnouncementTakesTheEgressPrefixesFromTheTranslator(t *testing.T) {
	cfg := &config.Config{Cap: config.Caps{
		Route: &babel.Routes{Announce: []schema.Announce{{Prefix: schema.MustPrefix("10.88.0.2/32")}}},
	}}
	c := &Client{}
	if routes := c.announced(cfg); len(routes) != 1 {
		t.Fatalf("announced %v with no translator, want cap.route alone", routes)
	}
	exit := netip.MustParsePrefix("0.0.0.0/0")
	c.SetEgressAnnounce(func() []netip.Prefix { return []netip.Prefix{exit} })
	routes := c.announced(cfg)
	if len(routes) != 2 || routes[1].Destination != exit {
		t.Errorf("announced %v, want cap.route's list and the exit's own prefix", routes)
	}
}
