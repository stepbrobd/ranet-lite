package babel

import (
	"crypto/rand"
	"fmt"
	"net/netip"
	"time"

	"github.com/NickCao/ranet-lite/internal/netstack"
	"github.com/NickCao/ranet-lite/schema"
)

// Config is the cap.babel capability, parsed straight out of the file: the
// timers this speaker runs on and the cost it puts on a link. Every field left
// out keeps the speaker's own default, so a node that writes the block at all
// is changing one thing rather than restating all of them.
type Config struct {
	Hello  schema.Duration `yaml:"hello,omitempty" json:"hello,omitempty" toml:"hello,omitempty"`
	Update schema.Duration `yaml:"update,omitempty" json:"update,omitempty" toml:"update,omitempty"`
	// Quality names the estimator turning Hello loss into a cost, spelled as
	// BIRD spells it: "etx", which the fleet runs on these same tunnels, or
	// "none" to cost every live link alike however much it drops.
	Quality LinkQuality `yaml:"quality,omitempty" json:"quality,omitempty" toml:"quality,omitempty"`
	// Cost is the link cost, named after the BIRD babel interface options it
	// mirrors: a fixed rx cost plus up to rtt.weight scaled linearly between
	// rtt.min and rtt.max. Each of the four keeps the speaker's default on its
	// own, so writing one of them leaves the other three alone.
	Cost CostOptions `yaml:"cost,omitempty" json:"cost,omitempty" toml:"cost,omitempty"`
}

// Runtime is the half the speaker is handed rather than told: the router id
// and the link-local address it speaks from, which are generated when nothing
// names them, and the largest packet the device will carry. None of the three
// is a fact an operator writes down, so none of them is in the capability.
type Runtime struct {
	RouterID      [8]byte
	LinkLocalAddr netip.Addr
	// PacketSize is the maximum Babel UDP payload, its four-byte protocol
	// header included.
	PacketSize int
}

const maxInterval = 65535 * 10 * time.Millisecond

// HelloInterval and UpdateInterval are the intervals in force, the default
// filled in where the file left the field out. Two configurations have to be
// compared through these rather than as they were written: an omitted interval
// and one spelled out as its own default describe the same speaker.
func (c Config) HelloInterval() time.Duration {
	if c.Hello == 0 {
		// The RFC 8966 Appendix B default, which is also BIRD's and what the
		// fleet configures. At 20 seconds a peer that is up but silent is
		// declared dead after 70 rather than 14, which is a different network
		// from the one this is replacing. A node that would rather wake less
		// often sets cap.babel hello.
		return 4 * time.Second
	}
	return c.Hello.Duration()
}

func (c Config) UpdateInterval() time.Duration {
	if c.Update == 0 {
		// Cap before multiplying, including for invalid very large inputs.
		return 4 * min(c.HelloInterval(), maxInterval/4)
	}
	return c.Update.Duration()
}

// CostEffective is the link cost in force, each omitted field filled in with
// the package default and the estimator carried into it from the block above.
func (c Config) CostEffective() CostParams {
	cost := c.Cost.Params()
	cost.Quality = c.Quality
	return cost
}

// Effective is the speaker a block describes, every omitted field filled in.
// A reload compares two configurations through this rather than as they were
// written, since an omitted field and one spelled out as its own default
// describe the same speaker.
type Effective struct {
	Hello  time.Duration
	Update time.Duration
	Cost   CostParams
}

func (c Config) Effective() Effective {
	return Effective{Hello: c.HelloInterval(), Update: c.UpdateInterval(), Cost: c.CostEffective()}
}

// Validate checks the capability, defaults included, so a bad rx cost fails
// where the file is read rather than at speaker construction.
func (c Config) Validate() error {
	// Named one at a time, and by the interval in force rather than as the
	// file spells it: update defaults to four hellos, so a hello an operator
	// wrote is refused through update as often as through itself, and a
	// message naming neither field nor value says nothing about which line to
	// change.
	for _, named := range []struct {
		field    string
		interval time.Duration
	}{{"hello", c.HelloInterval()}, {"update", c.UpdateInterval()}} {
		if named.interval < 10*time.Millisecond || named.interval > maxInterval {
			return fmt.Errorf("babel: cap.babel %s is %s, and an interval is between 10ms and %s",
				named.field, named.interval, maxInterval)
		}
	}
	cost := c.CostEffective()
	if cost.RTT.Min < 0 || cost.RTT.Max < cost.RTT.Min {
		return fmt.Errorf("babel: cap.babel cost rtt min %s is negative or larger than rtt max %s", cost.RTT.Min, cost.RTT.Max)
	}
	// A link whose cost saturates is a link a neighbor cannot use at all, so a
	// configuration that reaches infinity at rtt max is rejected rather than
	// silently making the peer unreachable.
	if cost.RxCost == 0 || saturatingAdd(cost.RxCost, cost.RTT.Weight) == MetricInfinity {
		return fmt.Errorf("babel: cap.babel cost rx %d plus rtt weight %d must be between 1 and %d",
			cost.RxCost, cost.RTT.Weight, MetricInfinity-1)
	}
	return nil
}

// resolve fills in what the speaker was not given: a random router id and a
// random link-local address, and the packet size the device allows.
func (r Runtime) resolve() (Runtime, error) {
	if r.RouterID == ([8]byte{}) {
		rand.Read(r.RouterID[:])
	}
	if !r.LinkLocalAddr.IsValid() {
		r.LinkLocalAddr = randomLinkLocal()
	}
	if r.PacketSize == 0 {
		r.PacketSize = netstack.DefaultMTU - ipv6HeaderLen - udpHeaderLen
	}
	if !r.LinkLocalAddr.Is6() || !r.LinkLocalAddr.IsLinkLocalUnicast() || r.LinkLocalAddr.Zone() != "" {
		return r, fmt.Errorf("babel: local address must be an unzoned IPv6 link-local address")
	}
	// A full IPv6 Update with its Router-Id and a source prefix must fit in one
	// packet: 4 header, 12 Router-Id, 28 Update, 19 Source Prefix sub-TLV.
	if r.PacketSize < 63 || r.PacketSize > 65535-udpHeaderLen {
		return r, fmt.Errorf("babel: packet size must be between 63 and %d", 65535-udpHeaderLen)
	}
	return r, nil
}

func randomLinkLocal() netip.Addr {
	var b [16]byte
	b[0], b[1] = 0xfe, 0x80
	rand.Read(b[8:])
	return netip.AddrFrom16(b)
}
