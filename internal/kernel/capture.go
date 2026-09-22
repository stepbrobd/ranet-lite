package kernel

import (
	"net/netip"
	"time"
)

// DefaultCaptureGrace is how long a route that would capture this machine's
// own traffic stays installed after the last live session went away. It is ten
// seconds because the quantity it has to outlast is a reconnect and not an
// outage: a session that drops and is dialed again completes a handshake in
// well under that, while a session that is gone has already been silent for
// twice the dead peer detection interval before it stops counting as live. A
// longer grace buys nothing and is paid for in seconds during which the
// machine has no working network at all.
const DefaultCaptureGrace = 10 * time.Second

// capturesTheMachine reports a route that takes this machine's own traffic
// rather than a prefix of it. Two arms, and each comes from a measurement
// rather than from a rule of thumb about prefix lengths.
//
//   - Half the address space or more. That is how a default that does not
//     replace the host's own is written, 0.0.0.0/1 with 128.0.0.0/1 or ::/1
//     with 8000::/1, the spelling wg-quick and the tunnels on darwin use, and
//     a neighbor can announce one: the Update decoder bounds a prefix length
//     only at 32 and 128.
//
//   - Any prefix containing the family's unspecified address, however small.
//     That is the darwin kernel's own trigger, measured on Darwin 27.2.0 by
//     TestZMeasureWhichSetsStrandABoundSocket and kept as
//     TestDarwinStrandsABoundSocketOnlyThroughTheZeroAddress: a socket bound
//     with IP_BOUND_IF loses a destination exactly when the tun's unscoped
//     routes best-match both that destination and the all-zeros address of
//     its family. The scoped lookup falls back to a longest-prefix match on
//     the unspecified address and requires the answer to be on the bound
//     interface, so a route as small as 0.0.0.0/24 out of the tun takes the
//     fallback away. 0.0.0.0/24 with 192.0.2.0/24 strands; 64.0.0.0/2 with
//     192.0.2.0/24 does not.
//
// The second arm makes this a property of the set rather than of one
// route: no set can cover a family without some member containing that
// family's zero address, so holding those back breaks every full cover and
// restores the kernel's fallback. Measured: with 0.0.0.0/1 withdrawn,
// 128.0.0.0/1 alone leaves both probes reaching.
func capturesTheMachine(r Route) bool {
	if r.Destination.Bits() <= 1 {
		return true
	}
	return r.Destination.Contains(unspecifiedOf(r.Destination.Addr()))
}

// unspecifiedOf is the all-zeros address of a prefix's family.
func unspecifiedOf(address netip.Addr) netip.Addr {
	if address.Is4() {
		return netip.IPv4Unspecified()
	}
	return netip.IPv6Unspecified()
}

// CaptureRoutes is the routing the underlay depends on before the mesh may be
// handed this machine's own traffic. On darwin that is a default scoped to the
// interface the underlay socket is bound to, see UnderlayDefaults there;
// nothing implements it on linux, where a marked socket needs no route of its
// own.
//
// Ready both repairs and reports, per family. The reconciler calls it once a
// pass and drops from that pass every capturing route whose own family is
// uncovered, so such a route is neither installed nor left behind: a capture
// is never in the kernel while the family it captures has nothing to fall back
// on, on either edge.
type CaptureRoutes interface {
	Ready() (Covered, error)
}

// Covered is which families the underlay can fall back on.
//
// It is per family because the fallback is: a socket bound with IP_BOUND_IF
// resolves the unspecified address of the destination's own family, so a
// covered IPv4 does nothing for a socket carrying ESP to an IPv6 peer. A node
// whose host default is IPv4 on the bound interface and IPv6 on another is an
// ordinary dual-stack laptop, and answering "covered" for it installed ::/0
// out of the tun with nothing behind it.
type Covered struct{ V4, V6 bool }

// Has reports whether the family an address belongs to is covered.
func (c Covered) Has(address netip.Addr) bool {
	if address.Is4() {
		return c.V4
	}
	return c.V6
}

// MinCaptureGrace is the shortest grace a configuration may name. The gate is
// sampled once a reconcile pass and a pass is a route dump, an address dump
// and, where the underlay has routing of its own, a table read and two route
// lookups, so a grace shorter than this cannot be honored and only sets how
// often that happens. A second is already far below the twenty a session
// takes to stop counting as live.
const MinCaptureGrace = time.Second

// captureGate decides when the mesh may be handed this machine's own traffic.
//
// An exit announces a default and the reconciler installs it, and from then on
// every packet this machine sends leaves through the tun. That is the feature.
// It is also the failure: a node whose mesh has gone has no network at all,
// rather than the mesh being down and the uplink still working, and on a
// laptop the mesh goes for ordinary reasons -- wifi to ethernet, a dock, sleep
// and wake, a VPN started underneath. Nothing recovers from that on its own,
// because reaching the peers needs the network the default just took.
//
// So the gate holds three rules, which together turn that failure into a
// fallback:
//
//   - nothing capturing is installed until one session has been live, so a
//     node that comes up next to a stale announcement never takes it;
//   - it is withdrawn once no session has been live for the grace, so a node
//     that loses the mesh falls back to its own uplink;
//   - it is restored on the first live session, so the recovery needs nobody
//     to run a command.
//
// Whether a session is live is the caller's question to answer, and the answer
// this daemon gives is a session that has recently proved its peer is there,
// not one that is merely installed. The gate only counts them.
type captureGate struct {
	grace time.Duration
	// liveAt is when a session was last live, meaningful only once seen is
	// set. seen is the first rule: before any session has been live there is
	// no grace to run, and the gate is shut rather than counting down from a
	// moment that never happened.
	liveAt time.Time
	seen   bool
	open   bool
	// waiting is set while the grace is running, which is the one state that
	// needs a wake-up of its own: nothing else will happen at the moment it
	// expires, so a caller that only reconciles on a change would leave the
	// machine's traffic in a dead tun until the next periodic sweep.
	waiting bool
}

// sample records one liveness observation and reports whether a route that
// would capture the machine may be installed now. changed is set on the
// observation that flips the answer, so a caller says so once rather than
// once per pass.
func (g *captureGate) sample(now time.Time, live int) (open, changed bool) {
	was := g.open
	switch {
	case live > 0:
		g.seen, g.liveAt, g.open, g.waiting = true, now, true, false
	case !g.seen:
		g.open, g.waiting = false, false
	default:
		// Strictly less, so a grace of zero withdraws on the first pass that
		// finds nothing live rather than one pass later.
		g.open = now.Sub(g.liveAt) < g.grace
		g.waiting = g.open
	}
	return g.open, g.open != was
}

// deadline is when the next sample has to happen for the grace to be honored,
// for a caller that would otherwise wait for its own next wake-up.
//
// It answers while the gate is open, not only while the grace is running. A
// session stops counting as live because it went quiet, and nothing fires when
// that happens, so a gate waiting for its first idle sample would not learn of
// it until the periodic sweep: with a thirty second sweep behind a twenty
// second liveness window, a ten second grace took about a minute. Asking to be
// woken one grace after the last live sample bounds it at the grace plus one
// sample instead.
func (g *captureGate) deadline() (time.Time, bool) {
	if !g.open {
		return time.Time{}, false
	}
	return g.liveAt.Add(g.grace), true
}
