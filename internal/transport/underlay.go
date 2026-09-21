package transport

import (
	"errors"
	"fmt"
	"log/slog"
)

// Underlay is how this node keeps the one UDP socket carrying IKE and ESP out
// of the reach of the routes the mesh installs.
//
// It is one idea with two spellings, which is why it is one block rather than
// a setting per platform. A node that holds an address an exit announces ends
// up with a route out of its own tun covering the peers it reaches that tun
// through, and an underlay that follows it is a tunnel running inside itself.
// linux answers with a mark: the datagrams carry Mark, and a policy rule the
// operator owns sends marked traffic to a table that is not the mesh's. darwin
// has no marks, no rules and one forwarding table, and answers by binding the
// socket to the interface the host's own default route leaves by, which scopes
// its route lookups to that interface. On that platform the interface also has
// to carry a default of its own scoped to it, which internal/kernel writes; see
// UnderlayDefaults there for the measurement and for the ownership rules that
// keep it off the host's own default.
//
// Either one makes a real default out of the tun safe, and an exit-node client
// installs a real default. Without one the route has to go where no ordinary
// socket can see it, leaving a node that can hold a mesh address and cannot
// send its traffic through a mesh exit.
//
// The fields are refused by name on the platform that has no meaning for them,
// rather than accepted and ignored: a configuration written to keep the
// underlay out that quietly does nothing is the failure this exists to stop.
type Underlay struct {
	// Mark is SO_MARK on the socket, linux only, and zero for none. Pick a
	// mark nothing else on the host uses, and install the matching rule, such
	// as { fwmark = 0x726c, table = "main", priority = 40, family = "both" },
	// under cap.table.rules: this package writes none itself.
	Mark uint32 `yaml:"mark,omitempty" json:"mark,omitempty" toml:"mark,omitempty"`
	// Bind sets IP_BOUND_IF and IPV6_BOUND_IF to the interface the host's own
	// default route leaves by, darwin only. It needs Runtime.Links to say
	// which interface that is and to say when it changes, because a laptop
	// moves between wifi, ethernet, a dock and a VPN of its own, and a binding
	// left on the interface that is gone costs the machine every network it
	// has rather than only the mesh.
	//
	// It is not enough on its own: that interface also needs a default route
	// scoped to it, which macOS writes for every interface but the primary
	// one. Runtime.Routes writes the missing one, and this socket is moved
	// onto an interface only once that has happened.
	Bind bool `yaml:"bind,omitempty" json:"bind,omitempty" toml:"bind,omitempty"`
}

// Runtime carries what the caller resolves at startup rather than writes in a
// file. It is separate from Underlay so the setting stays a value that a
// config file, a control plane and a test can each produce whole.
type Runtime struct {
	// Links answers which interface the host's own traffic leaves by. Nil is
	// allowed only where Underlay.Bind is unset.
	Links LinkSource
	// Routes writes whatever the host needs before a socket bound to an
	// interface can reach anything off it. Nil leaves that to the operator,
	// and the probe after each binding says so.
	Routes UnderlayRoutes
}

// UnderlayRoutes is the seam onto the routing this socket depends on.
// internal/kernel implements it on darwin, where a socket bound to an
// interface still reads the shared forwarding table and therefore needs that
// interface to carry a default of its own.
//
// The two calls exist separately so a move leaves no window: Prepare makes the
// interface usable, then the socket moves onto it, then Settle takes down what
// the interface it left needed. Doing it in one call would either strand the
// socket on an interface whose route has gone, or leave the route behind.
type UnderlayRoutes interface {
	// Prepare makes index usable by a socket bound to it.
	Prepare(index int) error
	// Settle removes what was prepared for every interface but index.
	Settle(index int) error
}

// LinkSource is the seam onto the host's own routing. internal/kernel
// implements it on darwin over the PF_ROUTE socket it already reads, which
// keeps the route socket in the one package that speaks it: this one owns a
// socket, not a routing table.
type LinkSource interface {
	// DefaultInterface is the index of the interface the host's own default
	// route leaves by. A host with no default route at all is an ordinary
	// state on a laptop, and is reported as an error rather than as index
	// zero, which would read as "unbind".
	DefaultInterface() (int, error)
	// Changed carries one coalesced wake-up per batch of changes to the
	// host's routing, so a binding can follow the interface it named.
	Changed() <-chan struct{}
}

// refuse reports why this platform cannot apply u, or nil. Both spellings are
// platform facilities and each is refused by name where it does not exist,
// rather than accepted and ignored: a node configured to keep its underlay out
// of the mesh's routing and silently not doing it is a tunnel running inside
// itself, which reads as a peer that will not connect.
func (u Underlay) refuse() error {
	if u.Mark != 0 && !marksSockets {
		return errors.New("a socket mark is a linux facility and is set on no other platform")
	}
	if u.Bind && !bindsSockets {
		return errors.New("binding the underlay socket to an interface is a darwin facility and is set on no other platform")
	}
	return nil
}

// interfaceBinder is implemented by the bind on a platform that can move a
// live socket from one interface to another. Rebinding rather than reopening
// is deliberate: the socket carries every SA this node holds, and a new
// descriptor would drop all of them to follow a link change that the peers
// never saw.
type interfaceBinder interface {
	// bindInterface sets the socket's interface index, where zero unbinds.
	// routed says the caller has written the routing a bound socket needs on
	// that interface, which decides what an unreachable socket is reported as.
	bindInterface(index int, routed bool) error
}

// bindUnderlay resolves the interface a bound socket starts on. An error is
// reported and the socket is left unbound rather than refusing to start: a
// laptop with no network yet is the ordinary way this happens, and Hub.follow
// binds as soon as the host has a default route. Hub.UnderlayReady is how a
// caller tells the two apart.
func bindUnderlay(underlay Underlay, rt Runtime) (int, error) {
	if err := underlay.refuse(); err != nil {
		return 0, err
	}
	if !underlay.Bind {
		return 0, nil
	}
	if rt.Links == nil {
		return 0, errors.New("binding the underlay socket needs a link source")
	}
	index, err := rt.Links.DefaultInterface()
	if err != nil {
		slog.Warn("transport left the underlay socket unbound", "err", err,
			"detail", "the host has no default route yet, so the socket is bound once it has one")
		return 0, nil
	}
	return index, nil
}

// follow rebinds the socket whenever the host's default route moves to another
// interface. It runs for the life of the hub.
func (h *Hub) follow(links LinkSource, routes UnderlayRoutes) {
	changed := links.Changed()
	for {
		select {
		case <-h.done:
			return
		case <-changed:
		}
		index, err := links.DefaultInterface()
		if err != nil {
			// Left where it is rather than unbound. A host between two
			// networks has no default for a moment, and unbinding for that
			// moment hands the socket back to a forwarding table that may
			// carry a default out of our own tun.
			slog.Warn("transport cannot tell which interface the host's traffic leaves by", "err", err)
			continue
		}
		if err := h.moveUnderlay(index, routes); err != nil {
			slog.Warn("transport could not follow the host's default route", "interface_index", index, "err", err)
		}
	}
}

// moveUnderlay puts the socket on one interface in the order that leaves it
// usable throughout: the interface it is going to is made ready first, then
// the socket moves, then whatever the interface it left needed comes down. A
// Prepare that fails stops the move, because moving onto an interface that is
// not ready is the outage this sequence exists to avoid.
func (h *Hub) moveUnderlay(index int, routes UnderlayRoutes) error {
	if routes != nil {
		if err := routes.Prepare(index); err != nil {
			return fmt.Errorf("transport: prepare interface %d: %w", index, err)
		}
	}
	if err := h.bindUnderlayTo(index, routes != nil); err != nil {
		return err
	}
	if routes != nil {
		if err := routes.Settle(index); err != nil {
			return fmt.Errorf("transport: settle on interface %d: %w", index, err)
		}
	}
	return nil
}

// BindUnderlay moves the socket carrying IKE and ESP onto one interface, where
// zero unbinds it. A binding that would change nothing costs no syscall, so a
// link notification about some other interface is free.
func (h *Hub) BindUnderlay(index int) error {
	return h.bindUnderlayTo(index, false)
}

// bindUnderlayTo is BindUnderlay with what the caller knows about the routing.
// routed says this node writes the route a bound socket needs, which changes
// the probe afterwards from advice for an operator into a check that the
// mechanism worked.
func (h *Hub) bindUnderlayTo(index int, routed bool) error {
	binder, ok := h.bind.(interfaceBinder)
	if !ok {
		return fmt.Errorf("transport: this platform cannot bind a socket to an interface")
	}
	h.mu.Lock()
	unchanged := h.boundTo == index
	h.mu.Unlock()
	if unchanged {
		return nil
	}
	if err := binder.bindInterface(index, routed); err != nil {
		return err
	}
	h.mu.Lock()
	h.boundTo = index
	h.mu.Unlock()
	slog.Info("transport bound the underlay socket", "interface_index", index)
	return nil
}

// UnderlayReady reports whether the socket is where the configuration says it
// should be. A hub that was asked to bind and could not, because the host had
// no default route when it opened, answers false, and the route reconciler
// reads that before it hands this machine's own traffic to the mesh: an
// unbound socket under a real default out of the tun is the tunnel inside
// itself this whole block exists to prevent.
func (h *Hub) UnderlayReady() bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	return !h.underlay.Bind || h.boundTo != 0
}
