//go:build darwin && !ios

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"syscall"
	"unsafe"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
)

// rtSocket is the write side of PF_ROUTE. It is an interface because the only
// thing the reconciler ever sends is an RTM_ADD or an RTM_DELETE, and what
// those encode is the part worth testing without a kernel.
type rtSocket interface {
	// WriteRoute stamps the message with the routing message version, this
	// process's identifier and the next sequence number, then sends it.
	WriteRoute(*route.RouteMessage) error
	Close() error
}

// pfRoute is one PF_ROUTE socket carrying RTM_ADD and RTM_DELETE. The
// reconcile loop is its only caller, so seq needs no lock; notifications
// arrive on the monitor's separate socket precisely so an unsolicited message
// can never be mistaken for a reply.
type pfRoute struct {
	fd  int
	seq int
}

func dialRouteSocket() (*pfRoute, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("kernel: open routing socket: %w", err)
	}
	// darwin's socket(2) takes no SOCK_CLOEXEC, so the flag is a second call.
	// This process never execs, so the window between them cannot leak it.
	unix.CloseOnExec(fd)
	// the kernel broadcasts the result of every write to all routing sockets,
	// the writer included. The monitor is the one that wants them, so this
	// socket asks not to be told about itself and never has to be drained.
	if err := unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_USELOOPBACK, 0); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("kernel: silence the routing socket echo: %w", err)
	}
	return &pfRoute{fd: fd}, nil
}

func (s *pfRoute) WriteRoute(message *route.RouteMessage) error {
	s.seq++
	message.Version = unix.RTM_VERSION
	message.ID, message.Seq = uintptr(os.Getpid()), s.seq
	raw, err := message.Marshal()
	if err != nil {
		return fmt.Errorf("encode routing message: %w", err)
	}
	// route_output reports its result as the errno of the write itself, so
	// there is no reply to correlate and nothing to read back.
	_, err = unix.Write(s.fd, raw)
	return err
}

func (s *pfRoute) Close() error { return unix.Close(s.fd) }

// gone reports the errnos meaning the object is already in the state the
// request asked for, or that the device has been removed under us. Neither is
// a failure: the next reconcile pass would do nothing about them either.
func gone(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENXIO) || errors.Is(err, unix.EADDRNOTAVAIL)
}

// addressFromRouteAddr converts one routing socket address. The zone the
// kernel embeds in a link-local is dropped: a Route key is zoneless
// throughout, and the interface is already fixed by the index filter.
func addressFromRouteAddr(addr route.Addr) (netip.Addr, bool) {
	switch value := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(value.IP), true
	case *route.Inet6Addr:
		return netip.AddrFrom16(value.IP), true
	}
	return netip.Addr{}, false
}

// prefixMask is the netmask sockaddr the kernel takes in place of a prefix
// length, in the destination's own family.
func prefixMask(prefix netip.Prefix) (netip.Addr, bool) {
	mask := net.CIDRMask(prefix.Bits(), prefix.Addr().BitLen())
	if mask == nil {
		return netip.Addr{}, false
	}
	return netip.AddrFromSlice(mask)
}

// maskBits is the reverse. A mask whose ones are not contiguous denotes no
// prefix at all, which net.IPMask.Size reports as a zero total.
func maskBits(mask netip.Addr) (int, bool) {
	ones, total := net.IPMask(mask.AsSlice()).Size()
	if total == 0 {
		return 0, false
	}
	return ones, true
}

const (
	// the sizes of the darwin address ioctl request structures. Each one is
	// part of the ioctl number itself, so a structure this file builds at the
	// wrong size is rejected by the kernel rather than silently misread.
	sizeofIfAliasReq  = 64  // struct ifaliasreq
	sizeofIfReq       = 32  // struct ifreq
	sizeofIn6AliasReq = 128 // struct in6_aliasreq
	sizeofIn6IfReq    = 288 // struct in6_ifreq

	// _IOW as <sys/ioccom.h> spells it. The group is 'i', for the interface
	// ioctls.
	iocIn        uintptr = 0x80000000
	iocParamMask uintptr = 0x1fff
	iocGroupIf   uintptr = 'i'

	// golang.org/x/sys/unix carries the IPv4 address ioctls but neither IPv6
	// one, so _IOW('i', 26, struct in6_aliasreq) and
	// _IOW('i', 25, struct in6_ifreq) are spelled out here.
	siocAIfAddrIn6 = iocIn | (sizeofIn6AliasReq&iocParamMask)<<16 | iocGroupIf<<8 | 26
	siocDIfAddrIn6 = iocIn | (sizeofIn6IfReq&iocParamMask)<<16 | iocGroupIf<<8 | 25

	// ND6_INFINITE_LIFETIME. An address nothing renews has to be permanent or
	// nd6 expires it out from under the mesh.
	nd6InfiniteLifetime = 0xffffffff

	// offsets inside struct in6_aliasreq, which has no sockaddr padding and so
	// cannot be expressed as a run of equal-sized fields.
	offIn6AliasAddr    = 16
	offIn6AliasDstAddr = 44
	offIn6AliasMask    = 72
	offIn6AliasVLTime  = 120
	offIn6AliasPLTime  = 124
	offIn6IfReqAddr    = 16
	offIfAliasAddr     = 16
	offIfAliasDstAddr  = 32
	offIfAliasMask     = 48
	offIfReqAddr       = 16
	offSockaddrIn4Addr = 4
	offSockaddrIn6Addr = 8
)

// putSockaddrInet4 writes a sockaddr_in: length, family, a zero port and the
// address. A netmask is carried in the same shape, the shape ifconfig
// sends.
func putSockaddrInet4(buf []byte, address netip.Addr) {
	raw := address.As4()
	buf[0] = unix.SizeofSockaddrInet4
	buf[1] = unix.AF_INET
	copy(buf[offSockaddrIn4Addr:], raw[:])
}

func putSockaddrInet6(buf []byte, address netip.Addr) {
	raw := address.As16()
	buf[0] = unix.SizeofSockaddrInet6
	buf[1] = unix.AF_INET6
	copy(buf[offSockaddrIn6Addr:], raw[:])
}

// aliasRequest4 builds struct ifaliasreq for SIOCAIFADDR: the interface name
// and three sockaddr_in, each padded to the 16 bytes of a struct sockaddr.
//
// A utun is point to point, so in_ifinit refuses an alias without a
// destination. It is set to the address itself, which is the arrangement
// "ifconfig utunN inet A/n A" makes and the one the deployment wants: nothing
// on the far side of the tun answers to an address of its own, because the
// mesh picks the peer after the kernel hands over the packet.
func aliasRequest4(name string, prefix netip.Prefix) ([]byte, error) {
	mask, ok := prefixMask(prefix)
	if !ok {
		return nil, fmt.Errorf("%s has no netmask", prefix)
	}
	request := make([]byte, sizeofIfAliasReq)
	copy(request[:unix.IFNAMSIZ], name)
	putSockaddrInet4(request[offIfAliasAddr:], prefix.Addr())
	putSockaddrInet4(request[offIfAliasDstAddr:], prefix.Addr())
	putSockaddrInet4(request[offIfAliasMask:], mask)
	return request, nil
}

// aliasRequest6 builds struct in6_aliasreq for SIOCAIFADDR_IN6.
//
// ifra_dstaddr stays AF_UNSPEC. in6_update_ifa accepts that on a point to
// point link, whereas naming a destination is only meaningful for a /128 and
// the addresses the mesh hands a leaf are not all /128.
func aliasRequest6(name string, prefix netip.Prefix) ([]byte, error) {
	mask, ok := prefixMask(prefix)
	if !ok {
		return nil, fmt.Errorf("%s has no netmask", prefix)
	}
	request := make([]byte, sizeofIn6AliasReq)
	copy(request[:unix.IFNAMSIZ], name)
	putSockaddrInet6(request[offIn6AliasAddr:], prefix.Addr())
	putSockaddrInet6(request[offIn6AliasMask:], mask)
	binary.NativeEndian.PutUint32(request[offIn6AliasVLTime:], nd6InfiniteLifetime)
	binary.NativeEndian.PutUint32(request[offIn6AliasPLTime:], nd6InfiniteLifetime)
	return request, nil
}

// deleteRequest4 builds struct ifreq for SIOCDIFADDR, which matches on the
// address alone.
func deleteRequest4(name string, prefix netip.Prefix) []byte {
	request := make([]byte, sizeofIfReq)
	copy(request[:unix.IFNAMSIZ], name)
	putSockaddrInet4(request[offIfReqAddr:], prefix.Addr())
	return request
}

// deleteRequest6 builds struct in6_ifreq for SIOCDIFADDR_IN6. The union that
// follows the name is read as its sockaddr_in6 member here.
func deleteRequest6(name string, prefix netip.Prefix) []byte {
	request := make([]byte, sizeofIn6IfReq)
	copy(request[:unix.IFNAMSIZ], name)
	putSockaddrInet6(request[offIn6IfReqAddr:], prefix.Addr())
	return request
}

// ioctlRequest issues one ioctl with a request structure this package built.
// golang.org/x/sys/unix exposes only typed helpers on darwin and none of them
// covers an address request, so the syscall is made directly.
func ioctlRequest(fd int, request uintptr, argument []byte) error {
	_, _, errno := syscall.Syscall(syscall.SYS_IOCTL, uintptr(fd), request,
		uintptr(unsafe.Pointer(&argument[0])))
	if errno != 0 {
		return errno
	}
	return nil
}

// routeMonitor turns unsolicited routing messages into one coalesced wake-up.
// It parses just enough of each message to drop the ones for other interfaces,
// which stops the rest of the box's route churn from waking the
// reconciler. Its own writes still wake it once; the settle window in Run
// absorbs the burst and the following pass finds nothing to do.
type routeMonitor struct {
	file   *os.File
	index  int
	signal chan struct{}
	done   chan struct{}
}

func newRouteMonitor(index int) (*routeMonitor, error) {
	fd, err := unix.Socket(unix.AF_ROUTE, unix.SOCK_RAW, unix.AF_UNSPEC)
	if err != nil {
		return nil, fmt.Errorf("kernel: open route monitor socket: %w", err)
	}
	unix.CloseOnExec(fd)
	if err := unix.SetNonblock(fd, true); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("kernel: set the route monitor nonblocking: %w", err)
	}
	// a routing socket that overflows drops the excess without telling the
	// reader, unlike netlink's ENOBUFS, so a large receive buffer is the only
	// defense against a route flood and the periodic sweep the only backstop.
	_ = unix.SetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF, 1<<19)
	// the socket is nonblocking, so os.NewFile registers it with the runtime
	// poller and Close unblocks the reader without racing on the descriptor.
	monitor := &routeMonitor{
		file:   os.NewFile(uintptr(fd), "pf-route-monitor"),
		index:  index,
		signal: make(chan struct{}, 1),
		done:   make(chan struct{}),
	}
	go monitor.run()
	return monitor, nil
}

func (m *routeMonitor) run() {
	defer close(m.done)
	// a routing socket delivers one message per read and drops the rest of a
	// message that does not fit, so the buffer is far larger than the longest
	// one the kernel can send.
	buf := make([]byte, 8192)
	for {
		n, err := m.file.Read(buf)
		if err != nil {
			if errors.Is(err, os.ErrClosed) {
				return
			}
			// anything else is unexpected and would spin, so it is reported
			// and the monitor stops; the periodic sweep in Run remains as the
			// backstop.
			m.wake()
			slog.Warn("kernel route monitor stopped, falling back to the periodic sweep", "err", err)
			return
		}
		if m.interesting(buf[:n]) {
			m.wake()
		}
	}
}

// interesting reports whether one routing socket datagram changed a route out
// of the monitored interface. A message that will not parse still counts:
// something changed, and a reconcile pass is cheap next to missing it.
func (m *routeMonitor) interesting(buf []byte) bool {
	messages, err := route.ParseRIB(route.RIBTypeRoute, buf)
	if err != nil {
		return true
	}
	for _, message := range messages {
		rm, ok := message.(*route.RouteMessage)
		if !ok || rm.Index != m.index {
			continue
		}
		switch rm.Type {
		case unix.RTM_ADD, unix.RTM_DELETE, unix.RTM_CHANGE:
			return true
		}
	}
	return false
}

// wake never blocks: a reader that misses one coalesced signal sees the change
// on the next one, or on the periodic sweep.
func (m *routeMonitor) wake() {
	select {
	case m.signal <- struct{}{}:
	default:
	}
}

func (m *routeMonitor) Close() error {
	err := m.file.Close()
	<-m.done
	return err
}
