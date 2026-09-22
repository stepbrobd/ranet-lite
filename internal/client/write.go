package client

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/NickCao/ranet-lite/control"
)

// This file is the runtime's side of the control socket's write path: the four
// verbs of control.Sink and the operational state they own.
//
// None of them touches the configuration, which keeps its two entry points,
// the file and SIGHUP. What they act on is whether a subsystem the file
// already describes is running right now, which session this node holds for a
// peer, and when the next Child SA is negotiated. Every one of those is
// reversible, bounded and already in the file's gift, so the socket's mode
// stays the whole authorization story; see the control package doc for the
// line a fifth verb would have to stay inside.
//
// The state lives here and nowhere else. A restart starts everything the file
// names, and a reload leaves it alone: the trust document is rewritten every
// time any node joins the mesh, so a reload that started a subsystem again
// would undo a decision somebody took minutes earlier, on a schedule nobody
// chose.

// startedSubsystems is the state a node comes up in, which is the state its
// file describes.
func startedSubsystems() map[control.Subsystem]bool {
	running := make(map[control.Subsystem]bool, len(control.Subsystems))
	for _, name := range control.Subsystems {
		running[name] = true
	}
	return running
}

// SetReconcilerEnable hands the write path the route reconciler's own stop and
// start, as SetKernelStatus hands it the reconciler's view of itself and for
// the same reason: the command builds the reconciler because it owns the
// kernel, and this owns the mesh. Without it the verb refuses by name, which
// is the honest answer for a node configuring its routes externally.
func (c *Client) SetReconcilerEnable(set func(bool)) { c.reconcilerEnable.Store(&set) }

// SetConfigPath records where this node's configuration was read from, so the
// reload verb re-reads the file SIGHUP re-reads. The daemon sets it; a client a
// test built by hand has none and reloads through ReloadFrom with its own path.
func (c *Client) SetConfigPath(path string) { c.configPath.Store(&path) }

// SetSubsystem stops or starts one subsystem, reporting whether the state moved
// and refusing a subsystem this node does not run.
func (c *Client) SetSubsystem(name control.Subsystem, on bool) (control.Result, error) {
	if !slices.Contains(control.Subsystems, name) {
		return control.Result{}, fmt.Errorf("control: no subsystem is called %q, so nothing changed: this node runs %s",
			name, strings.Join(control.SubsystemNames(), ", "))
	}
	if err := c.subsystemRuns(name); err != nil {
		return control.Result{}, err
	}
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	if c.running[name] == on {
		return control.Result{Acted: []string{string(name)},
			Detail: fmt.Sprintf("the %s was already %s", name, startedStopped(on))}, nil
	}
	// The effect before the record, under the lock a second write would have
	// to take, so no reader is told a subsystem is stopped while it is still
	// acting and two writes cannot interleave their two halves.
	c.applySubsystem(name, on)
	c.running[name] = on
	log.Printf("control: the %s is %s", name, startedStopped(on))
	return control.Result{Acted: []string{string(name)},
		Detail: fmt.Sprintf("the %s is %s", name, startedStopped(on))}, nil
}

// subsystemRuns refuses a subsystem this node's file never turned on. It is a
// refusal rather than a quiet success because an operator told "steering is
// stopped" by a node that never steered has been told nothing, and the answer
// they need is which of their assumptions is wrong.
func (c *Client) subsystemRuns(name control.Subsystem) error {
	switch name {
	case control.SubsystemReconciler:
		if c.reconcilerEnable.Load() == nil {
			return errors.New("control: this node reconciles no routes, so there is nothing to stop: it writes no cap.table block and its routes are configured outside it")
		}
	case control.SubsystemSteering:
		if c.Mesh.Steering() == nil {
			return errors.New("control: this node steers nothing, so there is nothing to stop: cap.segment configures no steer policy")
		}
	case control.SubsystemResponder:
		if !c.config().Link.Listen {
			return errors.New("control: this node answers no dials, so there is nothing to stop: link.listen is off")
		}
	}
	return nil
}

// applySubsystem pushes the decision to whoever acts on it. Each subsystem
// keeps its own flag where its hot path can read it without reaching back
// through this lock, and the responder reads the record itself because it is
// consulted once per handshake rather than once per packet.
func (c *Client) applySubsystem(name control.Subsystem, on bool) {
	switch name {
	case control.SubsystemReconciler:
		if set := c.reconcilerEnable.Load(); set != nil {
			(*set)(on)
		}
	case control.SubsystemSteering:
		c.Mesh.SetSteeringEnabled(on)
	}
}

// subsystemRunning is the read the responder makes per inbound handshake.
func (c *Client) subsystemRunning(name control.Subsystem) bool {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	return c.running[name]
}

// disabledSubsystems is the stopped set a status reports, in the order the
// declaration lists them. Nil where everything is running, so the field is
// absent rather than empty on every healthy node.
func (c *Client) disabledSubsystems() []control.Subsystem {
	c.runningMu.Lock()
	defer c.runningMu.Unlock()
	var out []control.Subsystem
	for _, name := range control.Subsystems {
		if !c.running[name] {
			out = append(out, name)
		}
	}
	return out
}

func startedStopped(on bool) string {
	if on {
		return "running"
	}
	return "stopped"
}

// Redial drops the sessions this node holds for a peer and sets its dialers
// going again at once.
//
// The butte cutover measured what this is for: a peer holding a session whose
// far end is gone does not retry on its own, and one of them sat that way for
// sixteen minutes. This is that peer's own operator saying so, on the side
// that can act. The sessions go first and the dialers are woken after, so a
// dialer does not find the path still held and stand down for another
// reconnect delay.
func (c *Client) Redial(peer string) (control.Result, error) {
	if peer == "" {
		return control.Result{}, errors.New("control: redial takes the peer to redial")
	}
	dialers := c.matchingDialers(peer)
	dropped := c.sessions.closeMatching(peer)
	if len(dialers) == 0 && len(dropped) == 0 {
		return control.Result{}, fmt.Errorf("control: this node neither dials nor holds a session with %q, so there is nothing to redial", peer)
	}
	c.wakeDialers(dialers)
	acted := slices.Concat(dialers, dropped)
	slices.Sort(acted)
	log.Printf("control: redialing %s, %d session(s) closed", peer, len(dropped))
	return control.Result{Acted: slices.Compact(acted),
		Detail: fmt.Sprintf("closed %d session(s) and set %d dialer(s) going again",
			len(dropped), len(dialers))}, nil
}

// matchingDialers names the running peer loops for one peer.
func (c *Client) matchingDialers(peer string) []string {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	var out []string
	for path := range c.dialers {
		if matchesPeer(path, peer) {
			out = append(out, path)
		}
	}
	slices.Sort(out)
	return out
}

// wakeDialers cuts the reconnect delay short on the loops named, skipping any
// that ended in the meantime. A wake that finds the buffer full is dropped,
// because a loop with one ask already queued makes one attempt either way.
func (c *Client) wakeDialers(paths []string) {
	c.dialersMu.Lock()
	defer c.dialersMu.Unlock()
	for _, path := range paths {
		running, ok := c.dialers[path]
		if !ok {
			continue
		}
		select {
		case running.wake <- struct{}{}:
		default:
		}
	}
}

// Rekey asks one peer's sessions, or every session, to replace their Child SA.
func (c *Client) Rekey(peer string, all bool) (control.Result, error) {
	if all == (peer != "") {
		return control.Result{}, errors.New("control: rekey takes either a peer or every session, not both and not neither")
	}
	asked := c.sessions.rekeyMatching(peer, all)
	if len(asked) == 0 {
		if all {
			return control.Result{}, errors.New("control: this node holds no session, so there is nothing to rekey")
		}
		return control.Result{}, fmt.Errorf("control: this node holds no session with %q, so there is nothing to rekey", peer)
	}
	log.Printf("control: %d session(s) asked to replace their child SA", len(asked))
	return control.Result{Acted: asked,
		Detail: fmt.Sprintf("asked %d session(s) to replace their child SA; the new SPIs appear under sessions as each lands", len(asked))}, nil
}

// Reload re-reads the configuration file and the trust document it names, as
// SIGHUP does, so a supervisor is not the only way to ask.
func (c *Client) Reload() (control.Result, error) {
	path := c.configPath.Load()
	if path == nil || *path == "" {
		return control.Result{}, errors.New("control: this node was never told which file it was configured from, so there is nothing to re-read")
	}
	if err := c.ReloadFrom(*path); err != nil {
		return control.Result{}, err
	}
	return control.Result{Acted: []string{*path},
		Detail: "re-read " + *path + " and the trust document it names"}, nil
}
