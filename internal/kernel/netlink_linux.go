//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"

	"golang.org/x/sys/unix"
)

// nlConn is one rtnetlink socket used for synchronous request and reply. The
// reconcile loop is its only caller, so it needs no locking; notifications
// arrive on a separate socket precisely so an unsolicited message can never be
// mistaken for a reply.
type nlConn struct {
	fd  int
	pid uint32
	seq uint32
	buf []byte
}

func dialNetlink() (*nlConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_ROUTE)
	if err != nil {
		return nil, fmt.Errorf("kernel: open rtnetlink socket: %w", err)
	}
	// binding with no port lets the kernel pick one, so several sockets in
	// this process and several processes on the box can coexist.
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("kernel: bind rtnetlink socket: %w", err)
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("kernel: read rtnetlink socket name: %w", err)
	}
	local, ok := name.(*unix.SockaddrNetlink)
	if !ok {
		_ = unix.Close(fd)
		return nil, errors.New("kernel: rtnetlink socket is not a netlink socket")
	}
	return &nlConn{fd: fd, pid: local.Pid, buf: make([]byte, 64*1024)}, nil
}

func (c *nlConn) Close() error { return unix.Close(c.fd) }

// nlMessage is one parsed netlink message: the header fields this package
// uses, plus the body with its fixed struct and trailing attributes.
type nlMessage struct {
	Kind  uint16
	Flags uint16
	Seq   uint32
	Pid   uint32
	Data  []byte
}

// execute sends one request and collects every reply the kernel sends for it.
// A dump ends at NLMSG_DONE and a modify request at its NLMSG_ERROR ack, so
// every modify request must carry NLM_F_ACK or this blocks forever. A nonzero
// ack comes back as the errno it carries; nothing is discarded quietly.
func (c *nlConn) execute(kind, flags uint16, body []byte) ([]nlMessage, error) {
	c.seq++
	seq := c.seq
	request := make([]byte, unix.SizeofNlMsghdr+len(body))
	binary.NativeEndian.PutUint32(request[0:], uint32(len(request)))
	binary.NativeEndian.PutUint16(request[4:], kind)
	binary.NativeEndian.PutUint16(request[6:], flags|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(request[8:], seq)
	binary.NativeEndian.PutUint32(request[12:], c.pid)
	copy(request[unix.SizeofNlMsghdr:], body)
	if err := unix.Sendto(c.fd, request, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var replies []nlMessage
	for {
		messages, err := c.receive()
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Seq != seq || message.Pid != c.pid {
				continue // a late reply to an abandoned request
			}
			switch message.Kind {
			case unix.NLMSG_NOOP:
			case unix.NLMSG_DONE:
				return replies, nil
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return nil, errors.New("kernel: truncated netlink error")
				}
				if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
					return nil, unix.Errno(-code)
				}
				return replies, nil
			default:
				replies = append(replies, message)
				if message.Flags&unix.NLM_F_MULTI == 0 {
					return replies, nil
				}
			}
		}
	}
}

// receive reads one datagram whole. MSG_PEEK with MSG_TRUNC reports the real
// length first, so a dump larger than the current buffer grows it instead of
// silently losing the tail.
func (c *nlConn) receive() ([]nlMessage, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, unix.MSG_PEEK|unix.MSG_TRUNC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if n <= len(c.buf) {
			break
		}
		c.buf = make([]byte, n)
	}
	for {
		n, from, err := unix.Recvfrom(c.fd, c.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			return nil, errors.New("kernel: rtnetlink reply did not come from the kernel")
		}
		// parsed messages point into the buffer they came from, and a
		// multipart dump arrives as several datagrams, so each one gets its
		// own copy rather than being overwritten by the next.
		return parseMessages(slices.Clone(c.buf[:n]))
	}
}

// parseMessages splits one datagram into messages. A length running past the
// buffer is an error rather than a short read, so a truncated dump can never
// look like a complete one.
func parseMessages(buf []byte) ([]nlMessage, error) {
	var out []nlMessage
	for len(buf) >= unix.SizeofNlMsghdr {
		length := int(binary.NativeEndian.Uint32(buf[0:]))
		if length < unix.SizeofNlMsghdr || length > len(buf) {
			return nil, errors.New("kernel: malformed netlink message length")
		}
		out = append(out, nlMessage{
			Kind:  binary.NativeEndian.Uint16(buf[4:]),
			Flags: binary.NativeEndian.Uint16(buf[6:]),
			Seq:   binary.NativeEndian.Uint32(buf[8:]),
			Pid:   binary.NativeEndian.Uint32(buf[12:]),
			Data:  buf[unix.SizeofNlMsghdr:length],
		})
		next := nlmsgAlign(length)
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return out, nil
}

// attributes iterates the rtnetlink attributes that follow a fixed header of
// offset bytes. A malformed attribute ends the iteration: the kernel never
// emits one, and a half-decoded message fails the ownership checks that follow
// rather than being acted on.
func (m nlMessage) attributes(offset int) iter.Seq2[uint16, []byte] {
	return func(yield func(uint16, []byte) bool) {
		if len(m.Data) < offset {
			return
		}
		buf := m.Data[offset:]
		for len(buf) >= unix.SizeofRtAttr {
			length := int(binary.NativeEndian.Uint16(buf[0:]))
			kind := binary.NativeEndian.Uint16(buf[2:])
			if length < unix.SizeofRtAttr || length > len(buf) {
				return
			}
			if !yield(kind, buf[unix.SizeofRtAttr:length]) {
				return
			}
			next := rtaAlign(length)
			if next >= len(buf) {
				return
			}
			buf = buf[next:]
		}
	}
}

// link resolves a device name to its index and the index of its master, using
// a keyed RTM_GETLINK rather than a dump.
func (c *nlConn) link(name string) (index, master uint32, err error) {
	body := make([]byte, unix.SizeofIfInfomsg)
	body = putAttrString(body, unix.IFLA_IFNAME, name)
	replies, err := c.execute(unix.RTM_GETLINK, 0, body)
	if err != nil {
		return 0, 0, err
	}
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWLINK || len(reply.Data) < unix.SizeofIfInfomsg {
			continue
		}
		index = binary.NativeEndian.Uint32(reply.Data[4:])
		for kind, value := range reply.attributes(unix.SizeofIfInfomsg) {
			if kind == unix.IFLA_MASTER && len(value) == 4 {
				master = binary.NativeEndian.Uint32(value)
			}
		}
		return index, master, nil
	}
	return 0, 0, unix.ENODEV
}

// linkName is the reverse lookup, for turning a master index back into the
// name the operator wrote in the configuration.
func (c *nlConn) linkName(index uint32) (string, error) {
	body := make([]byte, unix.SizeofIfInfomsg)
	binary.NativeEndian.PutUint32(body[4:], index)
	replies, err := c.execute(unix.RTM_GETLINK, 0, body)
	if err != nil {
		return "", err
	}
	for _, reply := range replies {
		if reply.Kind != unix.RTM_NEWLINK {
			continue
		}
		for kind, value := range reply.attributes(unix.SizeofIfInfomsg) {
			if kind == unix.IFLA_IFNAME {
				return unix.ByteSliceToString(value), nil
			}
		}
	}
	return "", unix.ENODEV
}

// putAttr appends one rtnetlink attribute, padded the way the kernel's own
// RTA_ALIGN pads it. The length field stays unpadded, as the kernel expects.
func putAttr(buf []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	start := len(buf)
	buf = append(buf, make([]byte, rtaAlign(length))...)
	binary.NativeEndian.PutUint16(buf[start:], uint16(length))
	binary.NativeEndian.PutUint16(buf[start+2:], kind)
	copy(buf[start+unix.SizeofRtAttr:], value)
	return buf
}

func putAttrU32(buf []byte, kind uint16, value uint32) []byte {
	var raw [4]byte
	binary.NativeEndian.PutUint32(raw[:], value)
	return putAttr(buf, kind, raw[:])
}

func putAttrString(buf []byte, kind uint16, value string) []byte {
	return putAttr(buf, kind, append([]byte(value), 0))
}

func nlmsgAlign(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

func rtaAlign(n int) int { return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1) }

// addressBytes is the wire form of an address: four bytes for IPv4 and sixteen
// otherwise. A 4-in-6 address stays sixteen bytes, because sadr keeps such a
// prefix in its IPv6 table and the kernel would too.
func addressBytes(address netip.Addr) []byte {
	if address.Is4() {
		raw := address.As4()
		return raw[:]
	}
	raw := address.As16()
	return raw[:]
}

// addressFromBytes decides the family from the attribute length, exactly as
// the kernel wrote it, so a mapped IPv6 address is not mistaken for IPv4.
func addressFromBytes(raw []byte) (netip.Addr, bool) {
	address, ok := netip.AddrFromSlice(raw)
	if !ok {
		return netip.Addr{}, false
	}
	return address.WithZone(""), true
}

func unspecified(family uint8) netip.Addr {
	if family == unix.AF_INET {
		return netip.AddrFrom4([4]byte{})
	}
	return netip.AddrFrom16([16]byte{})
}

// gone reports the errnos meaning the object is already in the state the
// request asked for, or that the device has been removed under us. Neither is
// a failure: the next reconcile pass would do nothing about them either.
func gone(err error) bool {
	return errors.Is(err, unix.ESRCH) || errors.Is(err, unix.ENOENT) ||
		errors.Is(err, unix.ENODEV) || errors.Is(err, unix.EADDRNOTAVAIL)
}
