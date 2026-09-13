package babel

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

// Config controls the point-to-point stub speaker. Zero fields use defaults.
type Config struct {
	RouterID       [8]byte
	LinkLocalAddr  netip.Addr
	HelloInterval  time.Duration
	UpdateInterval time.Duration
	Cost           CostParams
	// Maximum Babel UDP payload, including its four-byte protocol header.
	PacketSize int
	// NoTransit advertises only the prefixes this node originates, never a
	// route it learned from somebody else. The BIRD side of a ranet fleet
	// already draws that line with "export where proto = dbabel0". A node that
	// redistributes is offering to carry the mesh's traffic, and a leaf on a
	// laptop uplink should not: measured on one, the community started
	// forwarding third-party traffic through it within minutes. Refusing to
	// advertise can never close a loop, so this only ever narrows what the
	// feasibility distance already bounds.
	NoTransit bool
}

const maxInterval = 65535 * 10 * time.Millisecond

func (c *Config) setDefaults() {
	if c.HelloInterval == 0 {
		// The RFC 8966 Appendix B default, which is also BIRD's and what the
		// fleet configures. At 20 seconds a peer that is up but silent is
		// declared dead after 70 rather than 14, which is a different network
		// from the one this is replacing. A node that would rather wake less
		// often sets babel.hello_interval.
		c.HelloInterval = 4 * time.Second
	}
	if c.UpdateInterval == 0 {
		// Cap before multiplying, including for invalid very large inputs.
		c.UpdateInterval = 4 * min(c.HelloInterval, maxInterval/4)
	}
	if c.Cost == (CostParams{}) {
		c.Cost = DefaultCostParams()
	}
	if c.PacketSize == 0 {
		c.PacketSize = netstack.DefaultMTU - ipv6HeaderLen - udpHeaderLen
	}
}

// Validate checks the effective configuration, including default intervals.
func (c Config) Validate() error {
	c.setDefaults()
	for _, interval := range []time.Duration{c.HelloInterval, c.UpdateInterval} {
		if interval < 10*time.Millisecond || interval > maxInterval {
			return fmt.Errorf("babel: intervals must be between 10ms and %s", maxInterval)
		}
	}
	if c.LinkLocalAddr.IsValid() && (!c.LinkLocalAddr.Is6() || !c.LinkLocalAddr.IsLinkLocalUnicast() || c.LinkLocalAddr.Zone() != "") {
		return fmt.Errorf("babel: local address must be an unzoned IPv6 link-local address")
	}
	if c.Cost.RTTMin < 0 || c.Cost.RTTMax < c.Cost.RTTMin {
		return fmt.Errorf("babel: rtt min must be nonnegative and no larger than rtt max")
	}
	// A link whose cost saturates is a link a neighbor cannot use at all, so a
	// configuration that reaches infinity at RTTMax is rejected rather than
	// silently making the peer unreachable.
	if c.Cost.RxCost == 0 || saturatingAdd(c.Cost.RxCost, c.Cost.RTTCost) == MetricInfinity {
		return fmt.Errorf("babel: rxcost plus rtt cost must be between 1 and %d", MetricInfinity-1)
	}
	// A full IPv6 Update with its Router-Id and a source prefix must fit in one
	// packet: 4 header, 12 Router-Id, 28 Update, 19 Source Prefix sub-TLV.
	if c.PacketSize < 63 || c.PacketSize > 65535-udpHeaderLen {
		return fmt.Errorf("babel: packet size must be between 63 and %d", 65535-udpHeaderLen)
	}
	return nil
}

func randomLinkLocal() netip.Addr {
	var b [16]byte
	b[0], b[1] = 0xfe, 0x80
	rand.Read(b[8:])
	return netip.AddrFrom16(b)
}
