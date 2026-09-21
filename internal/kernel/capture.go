package kernel

import "time"

// DefaultCaptureGrace is how long a route that would capture this machine's
// own traffic stays installed after the last live session went away. It is ten
// seconds because the quantity it has to outlast is a reconnect and not an
// outage: a session that drops and is dialed again completes a handshake in
// well under that, while a session that is gone has already been silent for
// twice the dead peer detection interval before it stops counting as live. A
// longer grace buys nothing and is paid for in seconds during which the
// machine has no working network at all.
const DefaultCaptureGrace = 10 * time.Second

// capturesTheMachine reports a route that carries this machine's own traffic
// rather than a prefix of it. Half the address space counts, because that is
// how a default that does not replace the host's own is written: 0.0.0.0/1
// with 128.0.0.0/1, or ::/1 with 8000::/1, the spelling wg-quick and the
// tunnels on darwin use. The pair wins the lookup outright rather than
// colliding, and a neighbor can announce one: the Update decoder bounds a
// prefix length only at 32 and 128.
func capturesTheMachine(r Route) bool { return r.Destination.Bits() <= 1 }

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

// deadline is when the grace expires, for a caller that has to run a pass then
// rather than wait for its next wake-up. It reports false whenever no grace is
// running, which includes a gate that is already shut.
func (g *captureGate) deadline() (time.Time, bool) {
	if !g.waiting {
		return time.Time{}, false
	}
	return g.liveAt.Add(g.grace), true
}
