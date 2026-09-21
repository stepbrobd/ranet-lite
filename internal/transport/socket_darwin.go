//go:build darwin

package transport

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// This backend exists for one option the portable one cannot offer:
// IP_BOUND_IF and IPV6_BOUND_IF, which scope the socket carrying IKE and ESP
// to one interface. Nothing else on darwin keeps an underlay out of the mesh's
// own routing: there are no marks, no policy rules and one table shared by
// every program, so a real default route out of the mesh tun would otherwise
// carry this node's own ESP into the tunnel that ESP is carrying.
//
// Scoping the socket is necessary and, on this kernel, not sufficient. See
// reportBoundReach for what else the host needs and for the measurement.
//
// The portable bind is wireguard's StdNetBind, which keeps its descriptors to
// itself, so there is no seam to set a socket option through. The socket work
// here is otherwise the plainest form of what that one does: one datagram per
// read, one write per packet. darwin has neither recvmmsg nor UDP
// segmentation, so the batching the linux backend is built around has nothing
// to stand on here.

// darwinEndpoint is one peer address this socket sends to. A received datagram
// carries no reply source address, the same as under the portable bind, so an
// endpoint is the peer and nothing else.
type darwinEndpoint struct{ addr netip.AddrPort }

func (*darwinEndpoint) transportEndpoint() {}
func (e *darwinEndpoint) String() string   { return e.addr.String() }

// AddrPort drops the zone a link-local address arrives with. NAT detection
// hashes what this returns (RFC 7296 section 2.23), and the linux backend
// reaches these addresses through a sockaddr that carries no zone, so keeping
// one here would make the two ends of one mesh hash differently.
func (e *darwinEndpoint) AddrPort() netip.AddrPort {
	return netip.AddrPortFrom(e.addr.Addr().WithZone(""), e.addr.Port())
}

// darwinSocket is one bound UDP socket of one family. raw is retained for the
// whole life of the socket so the interface binding can be moved without
// reopening it: the socket carries every SA this node holds, and a new
// descriptor would drop all of them to follow a link change no peer saw.
type darwinSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	ipv6 bool
}

// boundInterfaceOption is the level and option name that binds this family's
// socket to one interface.
func (s *darwinSocket) boundInterfaceOption() (level, option int) {
	if s.ipv6 {
		return unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
	}
	return unix.IPPROTO_IP, unix.IP_BOUND_IF
}

func (s *darwinSocket) setBoundInterface(index int) error {
	level, option := s.boundInterfaceOption()
	var setErr error
	if err := s.raw.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), level, option, index)
	}); err != nil {
		return err
	}
	return setErr
}

// darwinBind holds the one socket per family every session shares.
type darwinBind struct {
	// rebind serializes a move from one interface to the other, so the two
	// families cannot end up on different ones.
	rebind sync.Mutex
	v4, v6 *darwinSocket
}

func (b *darwinBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &darwinEndpoint{addr: netip.AddrPortFrom(addr.Addr().Unmap(), addr.Port())}, nil
}

func (b *darwinBind) Close() error {
	var errs []error
	for _, socket := range []*darwinSocket{b.v4, b.v6} {
		if socket != nil {
			errs = append(errs, socket.conn.Close())
		}
	}
	return errors.Join(errs...)
}

// bindInterface moves both families at once, where zero unbinds. A partial
// move is reported rather than left: one family on the old interface and one
// on the new is a node that reaches half its peers.
func (b *darwinBind) bindInterface(index int, routed bool) error {
	b.rebind.Lock()
	defer b.rebind.Unlock()
	var errs []error
	for _, socket := range []*darwinSocket{b.v4, b.v6} {
		if socket == nil {
			continue
		}
		if err := socket.setBoundInterface(index); err != nil {
			errs = append(errs, fmt.Errorf("transport: bind the underlay socket to interface %d: %w", index, err))
		}
	}
	if err := errors.Join(errs...); err != nil {
		return err
	}
	reportBoundReach(index, routed)
	return nil
}

// offLinkProbes are the destinations a bound socket is asked about, one per
// family, both from the documentation ranges so nothing is ever sent to a real
// host. connect on a UDP socket resolves a route and sends no packet, so this
// reads the forwarding table without touching the network.
var offLinkProbes = []netip.Addr{
	netip.MustParseAddr("192.0.2.1"),
	netip.MustParseAddr("2001:db8::1"),
}

// reportBoundReach checks that the binding left the socket able to reach
// anything at all, which on this platform does not follow from the binding.
//
// IP_BOUND_IF does not take a socket out of the forwarding table. Measured on
// Darwin 27.2.0 by TestDarwinBoundSocketNeedsAScopedDefault: a scoped lookup
// still finds the most specific route, and where that route leaves another
// interface, the lookup falls back only to a route already on the bound one.
// So an unscoped default out of the tun, the thing binding the socket is meant
// to make safe, takes the underlay with it unless the underlay's own interface
// carries a default of its own scoped to it. internal/kernel writes that route
// when the mesh is about to capture; routed says it did.
//
// Either way an unreachable socket is reported rather than refused: the node
// stops holding a capturing route once its sessions die, so the state is
// recoverable and a refusal here would turn a bad route into a dead daemon.
func reportBoundReach(index int, routed bool) {
	if index == 0 {
		return
	}
	var unreachable []string
	for _, probe := range offLinkProbes {
		if err := reachesWhenBound(index, probe); err != nil {
			unreachable = append(unreachable, probe.String())
		}
	}
	// Only when neither family can get off the link. A node on an IPv4-only
	// or IPv6-only uplink has one of these failing as a matter of course.
	if len(unreachable) < len(offLinkProbes) {
		return
	}
	if routed {
		slog.Warn("transport bound the underlay socket to an interface it still cannot reach off",
			"interface_index", index, "probes", strings.Join(unreachable, " "),
			"detail", "the default scoped to that interface was written and did not make it usable, so this node's own peers are unreachable while the mesh holds the address space")
		return
	}
	slog.Warn("transport bound the underlay socket to an interface it cannot reach off",
		"interface_index", index, "probes", strings.Join(unreachable, " "),
		"detail", "nothing here writes that interface's routing, so give it a default scoped to it, route -n add -net 0.0.0.0/0 <next hop> -ifscope <interface>")
}

// reachesWhenBound resolves one route the way the bound socket would. It opens
// its own descriptor rather than using the live one, because connect on the
// live socket would fix its destination.
func reachesWhenBound(index int, target netip.Addr) error {
	// Built in the branch rather than in an assignment the other branch
	// overwrites: As4 panics on an IPv6 address, and a composite literal is
	// evaluated whether or not its value survives.
	family, level, option := unix.AF_INET, unix.IPPROTO_IP, unix.IP_BOUND_IF
	var sa unix.Sockaddr
	if target.Is4() {
		sa = &unix.SockaddrInet4{Addr: target.As4(), Port: 9}
	} else {
		family, level, option = unix.AF_INET6, unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
		sa = &unix.SockaddrInet6{Addr: target.As16(), Port: 9}
	}
	fd, err := unix.Socket(family, unix.SOCK_DGRAM, 0)
	if err != nil {
		return err
	}
	defer unix.Close(fd)
	if err := unix.SetsockoptInt(fd, level, option, index); err != nil {
		return err
	}
	return unix.Connect(fd, sa)
}

func (b *darwinBind) Send(packets [][]byte, endpoint Endpoint) error {
	ep, ok := endpoint.(*darwinEndpoint)
	if !ok {
		return fmt.Errorf("transport: endpoint %T did not come from this bind", endpoint)
	}
	socket := b.v6
	if ep.addr.Addr().Is4() {
		socket = b.v4
	}
	if socket == nil {
		return unix.EAFNOSUPPORT
	}
	for _, packet := range packets {
		if _, err := socket.conn.WriteToUDPAddrPort(packet, ep.addr); err != nil {
			return err
		}
	}
	return nil
}

// receiver reads one datagram per call. The buffer is the receiver's own and
// its view stays valid until the next call, which is the contract every
// backend holds; the hub copies anything it keeps.
func (s *darwinSocket) receiver() receiveFunc {
	buf := make([]byte, readBufferSize)
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
		n, from, err := s.conn.ReadFromUDPAddrPort(buf)
		if err != nil {
			return 0, 0, err
		}
		bufs[0], sizes[0] = buf[:n], n
		endpoints[0] = &darwinEndpoint{addr: netip.AddrPortFrom(from.Addr().Unmap(), from.Port())}
		// Every datagram is handed straight through, so this bind refuses
		// none of its own; the hub counts the ones nothing wanted.
		return 1, 0, nil
	}
}

// darwin has no packet marks and no policy rules, and binds instead.
// Underlay.refuse reads these.
const (
	marksSockets = false
	bindsSockets = true
)

// openPacketBind takes the one socket this node's IKE and ESP share. index
// binds it to that interface, and zero leaves it following the forwarding
// table as every other socket on the machine does. routed says the caller has
// already written that interface's own routing; see reportBoundReach.
func openPacketBind(port uint16, underlay Underlay, index int, routed bool) (packetBind, []receiveFunc, uint16, error) {
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation; an explicitly requested port still fails.
	var err error
	for range 10 {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port, index)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
			if err == nil {
				// The first binding goes through the listen hook rather than
				// bindInterface, and it is the one that matters most: a node
				// starting next to the default a previous run installed has no
				// working underlay from its first datagram.
				reportBoundReach(index, routed)
			}
			return bind, receivers, bound, err
		}
	}
	return nil, nil, 0, err
}

func listenPacketBind(port uint16, index int) (packetBind, []receiveFunc, uint16, error) {
	b := new(darwinBind)
	var receivers []receiveFunc
	for i, network := range []string{"udp4", "udp6"} {
		ipv6 := i == 1
		var bindErr error
		lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
			if err := raw.Control(func(fd uintptr) {
				for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF} {
					// Tuning, so a kernel that clamps or refuses it costs
					// throughput and nothing else.
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, 7<<20)
				}
				if index == 0 {
					return
				}
				// Reported rather than ignored like the tuning above. This
				// binding keeps the ESP underlay out of the tun carrying it,
				// so a silent failure here is an underlay that disappears
				// into the overlay.
				level, option := unix.IPPROTO_IP, unix.IP_BOUND_IF
				if ipv6 {
					level, option = unix.IPPROTO_IPV6, unix.IPV6_BOUND_IF
				}
				bindErr = unix.SetsockoptInt(int(fd), level, option, index)
			}); err != nil {
				return err
			}
			return bindErr
		}}
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
				continue
			}
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket := &darwinSocket{conn: pc.(*net.UDPConn), ipv6: ipv6}
		if socket.raw, err = socket.conn.SyscallConn(); err != nil {
			_ = socket.conn.Close()
			_ = b.Close()
			return nil, nil, 0, err
		}
		if ipv6 {
			b.v6 = socket
		} else {
			b.v4 = socket
		}
		port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		receivers = append(receivers, socket.receiver())
	}
	if len(receivers) == 0 {
		return nil, nil, 0, unix.EAFNOSUPPORT
	}
	return b, receivers, port, nil
}
