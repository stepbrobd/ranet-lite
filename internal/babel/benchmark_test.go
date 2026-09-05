package babel

import (
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/NickCao/ranet-lite/internal/netstack"
)

func BenchmarkReceiveData(b *testing.B) {
	s, err := New(Config{}, &netstack.Mesh{Routes: netstack.NewRouteTable()})
	if err != nil {
		b.Fatal(err)
	}
	peer := netstack.NewPeer("peer", nil, nil)
	s.AddPeer(peer)
	for _, protocol := range []byte{6, 17} {
		name := "TCP"
		if protocol == 17 {
			name = "UDP"
		}
		b.Run(name, func(b *testing.B) {
			raw := make([]byte, 1400)
			raw[0], raw[6] = 0x60, protocol
			binary.BigEndian.PutUint16(raw[4:6], uint16(len(raw)-40))
			copy(raw[8:24], netip.MustParseAddr("fd00::1").AsSlice())
			copy(raw[24:40], netip.MustParseAddr("fd00::2").AsSlice())
			binary.BigEndian.PutUint16(raw[42:44], 1234)
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					if s.Receive(peer, raw) {
						b.Fatal("consumed ordinary data as Babel")
					}
				}
			})
		})
	}
}
