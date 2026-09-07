package transport

import (
	"encoding/binary"
	"fmt"
	"net"
	"os"
	"strconv"
	"syscall"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

// Linux's mmsghdr ends with a uint32 length; Go adds the same alignment
// padding as C on each supported architecture.
type udpMmsg struct {
	header unix.Msghdr
	length uint32
}

// A source address remains in kernel format until an IKE message needs it.
// ESP is demultiplexed by SPI and never needs a net.UDPAddr or IP allocation.
type udpSource [unix.SizeofSockaddrInet6]byte

func (*udpSource) Network() string { return "udp" }
func (s *udpSource) String() string {
	addr, err := s.endpoint()
	if err != nil {
		return "invalid UDP source"
	}
	return addr.String()
}

func (s *udpSource) endpoint() (*net.UDPAddr, error) {
	addr := &net.UDPAddr{Port: int(binary.BigEndian.Uint16(s[2:4]))}
	switch binary.NativeEndian.Uint16(s[:2]) {
	case unix.AF_INET:
		addr.IP = append(net.IP(nil), s[4:8]...)
	case unix.AF_INET6:
		addr.IP = append(net.IP(nil), s[8:24]...)
		if scope := binary.NativeEndian.Uint32(s[24:28]); scope != 0 {
			addr.Zone = strconv.FormatUint(uint64(scope), 10)
		}
	default:
		return nil, fmt.Errorf("transport: invalid UDP source family")
	}
	return addr, nil
}

type udpReader struct {
	conn     syscall.RawConn
	messages []ipv4.Message
	headers  []udpMmsg
	iovecs   []unix.Iovec
	sources  []udpSource
	receive  func(uintptr) bool
	n        int
	err      syscall.Errno
}

// The vectors and all receive storage stay fixed for this socket's lifetime.
// x/net's general ReadBatch repacks them and allocates source addresses on
// every call, including for ESP packets whose address is never consumed.
func newUDPReader(conn syscall.RawConn, messages []ipv4.Message) *udpReader {
	r := &udpReader{
		conn: conn, messages: messages,
		headers: make([]udpMmsg, len(messages)),
		iovecs:  make([]unix.Iovec, len(messages)),
		sources: make([]udpSource, len(messages)),
	}
	r.receive = r.recv
	for i := range messages {
		m, h := &messages[i], &r.headers[i].header
		r.iovecs[i].Base = &m.Buffers[0][0]
		r.iovecs[i].SetLen(len(m.Buffers[0]))
		h.Iov = &r.iovecs[i]
		h.SetIovlen(1)
		h.Name = &r.sources[i][0]
		h.Control = &m.OOB[0]
		m.Addr = &r.sources[i]
	}
	return r
}

func (r *udpReader) read() (int, error) {
	for i := range r.headers {
		h := &r.headers[i].header
		h.Namelen = uint32(len(r.sources[i]))
		h.SetControllen(len(r.messages[i].OOB))
	}
	if err := r.conn.Read(r.receive); err != nil {
		return 0, err
	}
	if r.err != 0 {
		return 0, os.NewSyscallError("recvmmsg", r.err)
	}
	for i := range r.n {
		h, m := &r.headers[i], &r.messages[i]
		m.N, m.NN, m.Flags = int(h.length), int(h.header.Controllen), int(h.header.Flags)
	}
	return r.n, nil
}

func (r *udpReader) recv(fd uintptr) bool {
	for {
		n, _, err := unix.Syscall6(unix.SYS_RECVMMSG, fd, uintptr(unsafe.Pointer(&r.headers[0])), uintptr(len(r.headers)), 0, 0, 0)
		if err == unix.EINTR {
			continue
		}
		r.n, r.err = int(n), err
		return err != unix.EAGAIN && err != unix.EWOULDBLOCK
	}
}
