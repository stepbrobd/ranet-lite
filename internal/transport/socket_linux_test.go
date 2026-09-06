package transport

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"
	"unsafe"

	"golang.org/x/net/ipv4"
	"golang.org/x/sys/unix"
)

type scriptedUDP struct {
	read  func([]ipv4.Message) (int, error)
	write func([]ipv4.Message) (int, error)
}

func (s scriptedUDP) ReadBatch(messages []ipv4.Message, _ int) (int, error) {
	return s.read(messages)
}
func (s scriptedUDP) WriteBatch(messages []ipv4.Message, _ int) (int, error) {
	return s.write(messages)
}

func TestUDPReceivePreservesGROOverflowAndFullBatchReads(t *testing.T) {
	reads := 0
	socket := &udpSocket{pc: scriptedUDP{read: func(messages []ipv4.Message) (int, error) {
		reads++
		if len(messages) != espSendBatch {
			t.Fatalf("receive vector has %d messages, want %d", len(messages), espSendBatch)
		}
		// Four 64-packet GRO messages exceed the caller's 128-packet vector.
		for i := range 4 {
			m := &messages[i]
			m.N = 64 * 16
			for j := range 64 {
				binary.BigEndian.PutUint32(m.Buffers[0][j*16:], 123) // ESP SPI
				binary.BigEndian.PutUint32(m.Buffers[0][j*16+4:], uint32(i*64+j))
			}
			control := appendUDPSegment(m.OOB[:0], 16)
			(*unix.Cmsghdr)(unsafe.Pointer(&control[0])).Type = unix.UDP_GRO
			m.NN = len(control)
		}
		return 4, nil
	}}}
	receive := socket.receiver()
	packets, sizes, endpoints := make([][]byte, 128), make([]int, 128), make([]Endpoint, 128)
	for batch := range 2 {
		n, err := receive(packets, sizes, endpoints)
		if err != nil || n != 128 || reads != 1 {
			t.Fatalf("batch %d: n=%d err=%v reads=%d", batch, n, err, reads)
		}
		for i := range n {
			if sizes[i] != 16 || binary.BigEndian.Uint32(packets[i][4:8]) != uint32(batch*128+i) {
				t.Fatalf("GRO segment %d in batch %d was lost or reordered", i, batch)
			}
			if endpoints[i] != nil {
				t.Fatal("ESP receive allocated an unused source endpoint")
			}
		}
	}
}

func TestUDPSendPartialGSOFallbackDoesNotDuplicatePackets(t *testing.T) {
	const count, size = 128, 20
	storage := make([]byte, count*size)
	packets := make([][]byte, count)
	for i := range packets {
		packets[i] = storage[i*size : (i+1)*size]
		packets[i][0] = byte(i)
	}
	var got []byte
	calls := 0
	socket := &udpSocket{pc: scriptedUDP{write: func(messages []ipv4.Message) (int, error) {
		calls++
		if calls == 1 {
			// One GSO message succeeds, then the device rejects the next.
			for offset := 0; offset < len(messages[0].Buffers[0]); offset += size {
				got = append(got, messages[0].Buffers[0][offset])
			}
			return 1, unix.EIO
		}
		for _, m := range messages {
			if len(m.OOB) != 0 || len(m.Buffers[0]) != size {
				t.Fatal("GSO fallback did not restore individual datagrams")
			}
			got = append(got, m.Buffers[0][0])
		}
		return len(messages), nil
	}}}
	socket.gso.Store(true)
	socket.send.New = func() any { return newUDPSendBatch() }
	b := &udpBind{v4: socket}
	if err := b.Send(packets, &udpEndpoint{addr: &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 4500}}); err != nil {
		t.Fatal(err)
	}
	want := make([]byte, count)
	for i := range want {
		want[i] = byte(i)
	}
	if !bytes.Equal(got, want) || socket.gso.Load() {
		t.Fatalf("partial fallback changed datagram order/count: %v", got)
	}
}

func TestUDPSendKeepsEmptyDatagramSeparate(t *testing.T) {
	b := newUDPSendBatch()
	first := make([]byte, 16, 64)
	packets := [][]byte{first, {}, []byte("last")}
	if got := b.prepare(packets, &udpEndpoint{addr: &net.UDPAddr{}}, true); got != 3 {
		t.Fatalf("got %d messages, want the empty datagram preserved", got)
	}
}

func TestUDPSendDoesNotOverwriteNonadjacentPackets(t *testing.T) {
	storage := bytes.Repeat([]byte{3}, 32)
	first, last := storage[:16], storage[16:]
	clear(first)
	middle := bytes.Repeat([]byte{2}, 8)
	packets := [][]byte{first, middle, last}
	b := newUDPSendBatch()
	if got := b.prepare(packets, &udpEndpoint{addr: &net.UDPAddr{}}, true); got != 3 {
		t.Fatalf("got %d messages, want three nonadjacent datagrams", got)
	}
	if !bytes.Equal(last, bytes.Repeat([]byte{3}, 16)) {
		t.Fatalf("coalescing overwrote an unsent datagram: %v", last)
	}
}

func TestUDPReceiveSkipsTruncatedMessagesAndPreservesGROTail(t *testing.T) {
	socket := &udpSocket{pc: scriptedUDP{read: func(messages []ipv4.Message) (int, error) {
		for i, flags := range []int{unix.MSG_TRUNC, unix.MSG_CTRUNC, 0} {
			m := &messages[i]
			m.N, m.Flags = 20, flags
			copy(m.Buffers[0], bytes.Repeat([]byte{1}, m.N))
		}
		control := appendUDPSegment(messages[2].OOB[:0], 8)
		(*unix.Cmsghdr)(unsafe.Pointer(&control[0])).Type = unix.UDP_GRO
		messages[2].NN = len(control)
		return 3, nil
	}}}
	packets, sizes, endpoints := make([][]byte, 128), make([]int, 128), make([]Endpoint, 128)
	n, err := socket.receiver()(packets, sizes, endpoints)
	if err != nil || n != 3 {
		t.Fatalf("receive: n=%d err=%v, want three intact GRO segments", n, err)
	}
	for i, want := range []int{8, 8, 4} {
		if sizes[i] != want || len(packets[i]) != want {
			t.Fatalf("segment %d length=%d, want %d", i, sizes[i], want)
		}
	}
}

func TestUDPKernelGSORoundTrip(t *testing.T) {
	for _, address := range []string{"127.0.0.1", "::1"} {
		t.Run(address, func(t *testing.T) {
			receiver, receivers, port, err := openPacketBind(0)
			if err != nil {
				t.Fatal(err)
			}
			defer receiver.Close()
			index, socket := 0, receiver.(*udpBind).v4
			if address == "::1" {
				index, socket = 1, receiver.(*udpBind).v6
			}
			if socket == nil {
				t.Skip("address family unavailable")
			}
			if receiver.(*udpBind).v4 == nil {
				index = 0
			}
			if err := socket.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
				t.Fatal(err)
			}
			sender, _, _, err := openPacketBind(0)
			if err != nil {
				t.Fatal(err)
			}
			defer sender.Close()
			ep, err := sender.ParseEndpoint(net.JoinHostPort(address, fmt.Sprint(port)))
			if err != nil {
				t.Fatal(err)
			}
			// More than one send/receive vector, including a short final segment.
			const count, size = 200, 64
			storage := make([]byte, count*size)
			packets := make([][]byte, count)
			for i := range packets {
				packets[i] = storage[i*size : (i+1)*size]
				binary.BigEndian.PutUint32(packets[i], 1)
				binary.BigEndian.PutUint32(packets[i][4:], uint32(i))
			}
			packets[count-1] = packets[count-1][:size/2]
			if err := sender.Send(packets, ep); err != nil {
				t.Fatal(err)
			}
			bufs, sizes, endpoints := make([][]byte, 128), make([]int, 128), make([]Endpoint, 128)
			seen := 0
			for seen < count {
				n, err := receivers[index](bufs, sizes, endpoints)
				if err != nil {
					t.Fatalf("received %d/%d packets: %v", seen, count, err)
				}
				for _, packet := range bufs[:n] {
					if seen >= count || !bytes.Equal(packet, packets[seen]) {
						t.Fatalf("packet %d was lost, reordered, or reframed", seen)
					}
					seen++
				}
			}
		})
	}
}
