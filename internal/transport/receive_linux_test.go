package transport

import (
	"encoding/binary"
	"net"
	"testing"

	"golang.org/x/sys/unix"
)

func TestUDPSourceEndpointOwnsAddress(t *testing.T) {
	for _, family := range []uint16{unix.AF_INET, unix.AF_INET6} {
		var source udpSource
		binary.NativeEndian.PutUint16(source[:2], family)
		binary.BigEndian.PutUint16(source[2:4], 4500)
		want, zone := net.ParseIP("192.0.2.1"), ""
		if family == unix.AF_INET {
			copy(source[4:8], want.To4())
		} else {
			want, zone = net.ParseIP("fe80::abcd"), "12"
			copy(source[8:24], want.To16())
			binary.NativeEndian.PutUint32(source[24:28], 12)
		}
		endpoint, err := source.endpoint()
		if err != nil {
			t.Fatal(err)
		}
		clear(source[:]) // the next recvmmsg is allowed to overwrite the source
		if endpoint.Port != 4500 || !endpoint.IP.Equal(want) || endpoint.Zone != zone {
			t.Fatalf("saved IKE endpoint changed after receive-buffer reuse: %v", endpoint)
		}
	}
}

// Include the real send and receive syscalls, holding packet count and
// receive offloads constant so address allocation is the only difference.
func BenchmarkUDPReceiveVector(b *testing.B) {
	for _, native := range []bool{false, true} {
		name := "generic"
		if native {
			name = "fixed"
		}
		b.Run(name, func(b *testing.B) {
			bind, _, port, err := openPacketBind(0, 0)
			if err != nil {
				b.Fatal(err)
			}
			defer bind.Close()
			socket := bind.(*udpBind).v4
			if socket == nil {
				b.Skip("IPv4 unavailable")
			}
			var optionErr error
			if err := socket.raw.Control(func(fd uintptr) {
				optionErr = unix.SetsockoptInt(int(fd), unix.IPPROTO_UDP, unix.UDP_GRO, 0)
			}); err != nil || optionErr != nil {
				b.Fatalf("disable receive GRO: %v %v", err, optionErr)
			}
			if !native {
				socket.raw = nil
			}
			receive := socket.receiver()
			sender, _, _, err := openPacketBind(0, 0)
			if err != nil {
				b.Fatal(err)
			}
			defer sender.Close()
			endpoint, err := sender.ParseEndpoint((&net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: int(port)}).String())
			if err != nil {
				b.Fatal(err)
			}
			const size = 1400
			storage := make([]byte, espSendBatch*size)
			packets := make([][]byte, espSendBatch)
			for i := range packets {
				packets[i] = storage[i*size : (i+1)*size]
				packets[i][0] = 1 // ESP, so no saved reply endpoint
			}
			bufs, sizes, endpoints := make([][]byte, espSendBatch), make([]int, espSendBatch), make([]Endpoint, espSendBatch)
			b.SetBytes(espSendBatch * size)
			b.ReportAllocs()
			b.ResetTimer()
			for b.Loop() {
				if err := sender.Send(packets, endpoint); err != nil {
					b.Fatal(err)
				}
				for received := 0; received < len(packets); {
					n, _, err := receive(bufs, sizes, endpoints)
					if err != nil {
						b.Fatal(err)
					}
					received += n
				}
			}
		})
	}
}
