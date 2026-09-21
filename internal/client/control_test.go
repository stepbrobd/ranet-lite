package client

import (
	"testing"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/control"
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
		Kernel:   config.Kernel{Addresses: []string{"2a0c:b641:69c:8c6::1/128"}},
		Segments: config.Segments{Local: []config.LocalSegment{{SID: "2a0c:b641:69c:8c6::1", Behavior: "End.DT46"}}},
	}
	if _, err := localSegments(cfg); err == nil {
		t.Error("a segment on one of this node's own addresses was accepted")
	}
	cfg.Kernel.Addresses = []string{"2a0c:b641:69c:8c6::9/128"}
	if _, err := localSegments(cfg); err != nil {
		t.Errorf("a segment beside an unrelated address was refused: %v", err)
	}
}

// A host address written with a prefix length is refused rather than masked,
// as the rule list refuses the same typo. Masking steers a whole prefix where
// one address was meant and says nothing about it.
func TestSteerSelectorWithHostBitsIsRefused(t *testing.T) {
	cfg := &config.Config{Segments: config.Segments{
		Source: "2a0c:b641:69c:8c0::1",
		Steer:  []config.SteerEntry{{From: "2602:f590::23:161:104:117/64", Via: []string{"2a0c:b641:69c:98d6::1"}}},
	}}
	if _, err := steerTable(cfg); err == nil {
		t.Error("a selector with bits below its prefix length was accepted")
	}
	cfg.Segments.Steer[0].From = "2602:f590::23:161:104:117/128"
	if _, err := steerTable(cfg); err != nil {
		t.Errorf("a host selector was refused: %v", err)
	}
}
