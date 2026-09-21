//go:build darwin

package transport

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"syscall"

	"golang.org/x/sys/unix"
)

// This backend exists for one option the portable one cannot offer:
// IP_BOUND_IF and IPV6_BOUND_IF, which take the socket carrying IKE and ESP
// out of the forwarding table entirely. Nothing else on darwin does: there are
// no marks, no policy rules and one table shared by every program, so a real
// default route out of the mesh tun would otherwise carry this node's own ESP
// into the tunnel that ESP is carrying. With the socket bound, the route can
// be a real default, which is the difference between a Mac that holds a mesh
// address and a Mac that can send its traffic through a mesh exit.
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

func (s *darwinSocket) bindInterface(index int) error {
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
func (b *darwinBind) bindInterface(index int) error {
	b.rebind.Lock()
	defer b.rebind.Unlock()
	var errs []error
	for _, socket := range []*darwinSocket{b.v4, b.v6} {
		if socket == nil {
			continue
		}
		if err := socket.bindInterface(index); err != nil {
			errs = append(errs, fmt.Errorf("transport: bind the underlay socket to interface %d: %w", index, err))
		}
	}
	return errors.Join(errs...)
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
// table as every other socket on the machine does.
func openPacketBind(port uint16, underlay Underlay, index int) (packetBind, []receiveFunc, uint16, error) {
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation; an explicitly requested port still fails.
	var err error
	for range 10 {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port, index)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
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
