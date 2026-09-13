package transport

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
	"golang.org/x/sys/unix"
)

type udpEndpoint struct {
	addr    *net.UDPAddr
	control []byte // immutable reply source address and interface
}

func (*udpEndpoint) transportEndpoint() {}
func (e *udpEndpoint) String() string   { return e.addr.String() }

func (e *udpEndpoint) AddrPort() netip.AddrPort {
	addr, ok := netip.AddrFromSlice(e.addr.IP)
	if !ok {
		return netip.AddrPort{}
	}
	return netip.AddrPortFrom(addr.Unmap(), uint16(e.addr.Port))
}

type udpBatchConn interface {
	ReadBatch([]ipv4.Message, int) (int, error)
	WriteBatch([]ipv4.Message, int) (int, error)
}

type udpSocket struct {
	conn *net.UDPConn
	raw  syscall.RawConn
	pc   udpBatchConn
	ipv6 bool
	gso  atomic.Bool
	send sync.Pool
}

type udpBind struct{ v4, v6 *udpSocket }

func (b *udpBind) ParseEndpoint(s string) (Endpoint, error) {
	addr, err := netip.ParseAddrPort(s)
	if err != nil {
		return nil, err
	}
	return &udpEndpoint{addr: net.UDPAddrFromAddrPort(addr)}, nil
}

func (b *udpBind) Close() error {
	var errs []error
	for _, socket := range []*udpSocket{b.v4, b.v6} {
		if socket != nil {
			errs = append(errs, socket.conn.Close())
		}
	}
	return errors.Join(errs...)
}

func openPacketBind(port uint16) (packetBind, []receiveFunc, uint16, error) {
	// The port selected by the IPv4 bind may already be occupied on IPv6.
	// Retry ephemeral allocation; an explicitly requested port still fails.
	var err error
	for range 10 {
		var bind packetBind
		var receivers []receiveFunc
		var bound uint16
		bind, receivers, bound, err = listenPacketBind(port)
		if port != 0 || !errors.Is(err, unix.EADDRINUSE) {
			return bind, receivers, bound, err
		}
	}
	return nil, nil, 0, err
}

func listenPacketBind(port uint16) (packetBind, []receiveFunc, uint16, error) {
	b := new(udpBind)
	var receivers []receiveFunc
	for i, network := range []string{"udp4", "udp6"} {
		lc := net.ListenConfig{Control: func(_, _ string, raw syscall.RawConn) error {
			return raw.Control(func(fd uintptr) {
				for _, option := range []int{unix.SO_RCVBUF, unix.SO_SNDBUF, unix.SO_RCVBUFFORCE, unix.SO_SNDBUFFORCE} {
					_ = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, option, 7<<20)
				}
				_ = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 1)
			})
		}}
		pc, err := lc.ListenPacket(context.Background(), network, fmt.Sprintf(":%d", port))
		if err != nil {
			if errors.Is(err, unix.EAFNOSUPPORT) || errors.Is(err, unix.EPROTONOSUPPORT) {
				continue
			}
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket := &udpSocket{conn: pc.(*net.UDPConn), ipv6: i == 1}
		socket.gso.Store(true)
		socket.send.New = func() any { return newUDPSendBatch() }
		if socket.ipv6 {
			p := ipv6.NewPacketConn(pc)
			socket.pc, b.v6 = p, socket
			err = p.SetControlMessage(ipv6.FlagDst|ipv6.FlagInterface, true)
		} else {
			p := ipv4.NewPacketConn(pc)
			socket.pc, b.v4 = p, socket
			err = p.SetControlMessage(ipv4.FlagDst|ipv4.FlagInterface, true)
		}
		if err != nil {
			_ = b.Close()
			return nil, nil, 0, err
		}
		socket.raw, err = socket.conn.SyscallConn()
		if err != nil {
			_ = b.Close()
			return nil, nil, 0, err
		}
		port = uint16(pc.LocalAddr().(*net.UDPAddr).Port)
		receivers = append(receivers, socket.receiver())
	}
	if len(receivers) == 0 {
		return nil, nil, 0, unix.EAFNOSUPPORT
	}
	return b, receivers, port, nil
}

// receiver reads a full recvmmsg vector even when UDP_GRO is enabled. Each
// message may contain many datagrams; excess segments are returned on later
// calls before any receive storage is reused. ESP does not need source-address
// objects: only IKE packets retain a reply endpoint.
func (s *udpSocket) receiver() receiveFunc {
	messages := make([]ipv4.Message, espSendBatch)
	for i := range messages {
		messages[i].Buffers = [][]byte{make([]byte, readBufferSize)}
		messages[i].OOB = make([]byte, 128)
	}
	read := func() (int, error) { return s.pc.ReadBatch(messages, 0) }
	if s.raw != nil {
		read = newUDPReader(s.raw, messages).read
	}
	var count, index, offset, segment, refused int
	return func(bufs [][]byte, sizes []int, endpoints []Endpoint) (int, int, error) {
		refused = 0
		if index == count {
			var err error
			count, err = read()
			if errors.Is(err, unix.ENOSYS) {
				// Older 32-bit kernels expose recvmmsg only via socketcall.
				read = func() (int, error) { return s.pc.ReadBatch(messages, 0) }
				count, err = read()
			}
			if err != nil {
				return 0, 0, err
			}
			index, offset, segment = 0, 0, 0
		}
		n := 0
		for index < count && n < len(bufs) {
			m := &messages[index]
			if offset == 0 {
				// Counted in datagrams, the unit the counter's help text names
				// and the third arm below already uses: one GRO
				// buffer is up to forty of them, so counting the message would
				// undercount by that much. A zero-length datagram is refused
				// too -- it arrived and goes nowhere, and leaving it out is
				// the "a flood reads as silence" case on the one platform this
				// is deployed on.
				if m.Flags&(unix.MSG_TRUNC|unix.MSG_CTRUNC) != 0 || m.N == 0 {
					refused += datagramsIn(m)
					index++
					continue
				}
				var err error
				segment, err = udpGROSize(m.OOB[:m.NN])
				if err != nil {
					// The segment size is exactly what would not parse, so
					// this is the one arm that cannot do better than one.
					refused++
					index++
					continue
				}
				if segment == 0 {
					segment = m.N
				}
			}
			end := min(offset+segment, m.N)
			raw := m.Buffers[0][offset:end]
			bufs[n], sizes[n], endpoints[n] = raw, len(raw), nil
			if len(raw) >= 4 && binary.BigEndian.Uint32(raw[:4]) == 0 {
				// A datagram whose control message will not parse is counted
				// and dropped, not returned as an error: receiveLoop fails the
				// whole hub on an error, which closes every session on this
				// node, and the GRO sizing two branches up already skips the
				// same class of failure. Without the endpoint the responder
				// cannot answer, so the datagram is of no use anyway.
				if ep, err := s.replyEndpoint(m); err == nil {
					endpoints[n] = ep
				} else {
					refused++
					offset = end
					if offset == m.N {
						index++
						offset = 0
					}
					continue
				}
			}
			n++
			offset = end
			if offset == m.N {
				index++
				offset = 0
			}
		}
		return n, refused, nil
	}
}

// datagramsIn is how many datagrams a received message carries, which is one
// unless the kernel coalesced it and said so. A control buffer that will not
// parse leaves one, which is the floor rather than a guess.
func datagramsIn(m *ipv4.Message) int {
	if m.N == 0 {
		return 1
	}
	segment, err := udpGROSize(m.OOB[:m.NN])
	if err != nil || segment <= 0 {
		return 1
	}
	return (m.N + segment - 1) / segment
}

func (s *udpSocket) replyEndpoint(m *ipv4.Message) (*udpEndpoint, error) {
	var addr *net.UDPAddr
	if source, ok := m.Addr.(*udpSource); ok {
		var err error
		addr, err = source.endpoint()
		if err != nil {
			return nil, err
		}
	} else {
		addr = m.Addr.(*net.UDPAddr)
	}
	ep := &udpEndpoint{addr: addr}
	if s.ipv6 {
		var cm ipv6.ControlMessage
		if err := cm.Parse(m.OOB[:m.NN]); err != nil {
			return nil, err
		}
		ep.control = (&ipv6.ControlMessage{Src: cm.Dst, IfIndex: cm.IfIndex}).Marshal()
	} else {
		var cm ipv4.ControlMessage
		if err := cm.Parse(m.OOB[:m.NN]); err != nil {
			return nil, err
		}
		ep.control = (&ipv4.ControlMessage{Src: cm.Dst, IfIndex: cm.IfIndex}).Marshal()
	}
	return ep, nil
}

func udpGROSize(control []byte) (int, error) {
	for len(control) >= unix.CmsgLen(0) {
		header, data, rest, err := unix.ParseOneSocketControlMessage(control)
		if err != nil {
			return 0, err
		}
		if header.Level == unix.IPPROTO_UDP && header.Type == unix.UDP_GRO {
			if len(data) < 2 {
				return 0, errors.New("transport: short UDP_GRO control message")
			}
			return int(binary.NativeEndian.Uint16(data)), nil
		}
		control = rest
	}
	return 0, nil
}

type udpSendBatch struct {
	messages [espSendBatch]ipv4.Message
	ends     [espSendBatch]int
}

func newUDPSendBatch() *udpSendBatch {
	b := new(udpSendBatch)
	for i := range b.messages {
		b.messages[i].Buffers = make([][]byte, 1)
		b.messages[i].OOB = make([]byte, 0, 128)
	}
	return b
}

func appendUDPSegment(control []byte, size int) []byte {
	start := len(control)
	control = append(control, make([]byte, unix.CmsgSpace(2))...)
	header := (*unix.Cmsghdr)(unsafe.Pointer(&control[start]))
	header.Level, header.Type = unix.IPPROTO_UDP, unix.UDP_SEGMENT
	header.SetLen(unix.CmsgLen(2))
	binary.NativeEndian.PutUint16(control[start+unix.CmsgLen(0):], uint16(size))
	return control
}

// prepare coalesces adjacent ciphertext from SealBatch without copying it.
// Nonadjacent packets stay separate: using spare capacity for packing could
// overwrite another packet that has not been sent yet.
func (b *udpSendBatch) prepare(packets [][]byte, ep *udpEndpoint, gso bool) int {
	n := 0
	for first := 0; first < len(packets); {
		payload := packets[first]
		size := len(payload)
		end := first + 1
		if gso && size > 0 {
			for end < len(packets) && end-first < 64 && len(packets[end]) > 0 && len(packets[end]) <= size &&
				len(payload)+len(packets[end]) <= min(cap(payload), 65507) {
				if &payload[len(payload):cap(payload)][0] != &packets[end][0] {
					break
				}
				payload = payload[:len(payload)+len(packets[end])]
				end++
				if len(packets[end-1]) < size {
					break
				}
			}
		}
		m := &b.messages[n]
		m.Buffers[0], m.Addr = payload, ep.addr
		m.OOB = append(m.OOB[:0], ep.control...)
		if end-first > 1 {
			m.OOB = appendUDPSegment(m.OOB, size)
		}
		b.ends[n] = end
		n++
		first = end
	}
	return n
}

func (b *udpBind) Send(packets [][]byte, endpoint Endpoint) error {
	ep := endpoint.(*udpEndpoint)
	socket := b.v4
	if ep.addr.IP.To4() == nil {
		socket = b.v6
	}
	if socket == nil {
		return unix.EAFNOSUPPORT
	}
	batch := socket.send.Get().(*udpSendBatch)
	defer socket.send.Put(batch)
	for len(packets) > 0 {
		gso := socket.gso.Load()
		n := batch.prepare(packets[:min(len(packets), espSendBatch)], ep, gso)
		sent, err := socket.pc.WriteBatch(batch.messages[:n], 0)
		for i := range n {
			batch.messages[i].Buffers[0], batch.messages[i].Addr = nil, nil
		}
		if sent > 0 {
			packets = packets[batch.ends[sent-1]:]
		}
		if err != nil {
			if gso && (errors.Is(err, unix.EIO) || errors.Is(err, unix.EINVAL) ||
				errors.Is(err, unix.ENOPROTOOPT) || errors.Is(err, unix.EOPNOTSUPP)) {
				socket.gso.Store(false)
				continue
			}
			return err
		}
		if sent == 0 {
			return errors.New("transport: UDP send made no progress")
		}
	}
	return nil
}
