package babel

import (
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestRTTReplyMayReferToAnOlderHello(t *testing.T) {
	s, neighbor, _ := captureSpeaker(t, Config{})
	now := time.Now()
	// Our next scheduled Hello overtakes their reply to a previous Hello.
	s.helloAction(neighbor, 2, now)
	ihu := EncodeIHU(IHU{RxCost: 32, Interval: 100, HasTS: true,
		OriginTS: uint32(now.Add(-50 * time.Millisecond).UnixMicro()), ReceiveTS: 1000})
	hello := EncodeHello(Hello{Seqno: 2, Interval: 100, HasTS: true, TxTS: 11_000})
	s.handlePacket(neighbor, EncodePacket([]RawTLV{hello, ihu}))
	if !neighbor.haveRTT || neighbor.measuredRTT < 40*time.Millisecond {
		t.Fatalf("valid older-Hello sample was discarded: %v, %s", neighbor.haveRTT, neighbor.measuredRTT)
	}
}

func TestIPv4ViaIPv6CompressionIsIndependent(t *testing.T) {
	var decoder PrefixDecoder
	for _, ae := range []uint8{AEIPv4, AEIPv4ViaIPv6} {
		ip := net.IPv4(10, ae, 1, 1)
		if _, err := decoder.Decode(EncodeUpdate(Update{AE: ae, Plen: 32, Prefix: ip}).Body); err != nil {
			t.Fatal(err)
		}
	}
	for _, ae := range []uint8{AEIPv4, AEIPv4ViaIPv6} {
		compressed := []byte{ae, updateFlagRouterID, 32, 3, 0, 100, 0, 1, 0, 32, 2}
		u, err := decoder.Decode(compressed)
		if err != nil || !u.Prefix.Equal(net.IPv4(10, ae, 1, 2)) || u.RouterID != ([8]byte{0, 0, 0, 0, 10, ae, 1, 2}) {
			t.Fatalf("AE %d compressed Update = %+v, %v", ae, u, err)
		}
	}
}

func TestIPv4ViaIPv6RequestsAndAnnouncements(t *testing.T) {
	s, neighbor, packets := captureSpeaker(t, Config{})
	prefix := netip.MustParsePrefix("10.0.0.1/32")
	s.Originate(prefix)
	for _, ae := range []uint8{AEIPv4, AEIPv4ViaIPv6} {
		for _, request := range []RawTLV{
			EncodeRouteRequest(RouteRequest{AE: ae, Prefix: prefix}),
			EncodeSeqnoRequest(SeqnoRequest{AE: ae, Prefix: prefix, RouterID: s.cfg.RouterID, Seqno: 1, HopCount: 64}),
		} {
			*packets = nil
			s.handlePacket(neighbor, EncodePacket([]RawTLV{request}))
			if len(*packets) != 1 {
				t.Fatalf("AE %d request produced %d replies", ae, len(*packets))
			}
			tlvs, err := DecodePacket((*packets)[0][48:])
			if err != nil {
				t.Fatal(err)
			}
			u, err := (&PrefixDecoder{}).Decode(tlvs[len(tlvs)-1].Body)
			if err != nil || u.AE != AEIPv4ViaIPv6 || !u.Prefix.Equal(prefix.Addr().AsSlice()) {
				t.Fatalf("reply does not advertise the IPv6 next hop: %+v, %v", u, err)
			}
		}
	}
}

func TestUnknownMandatoryExtensionsAreRejected(t *testing.T) {
	prefix := netip.MustParsePrefix("2001:db8::/64")
	for _, test := range []struct {
		name   string
		tlv    RawTLV
		decode func([]byte) error
	}{
		{"Hello", EncodeHello(Hello{Interval: 100}), func(b []byte) error { _, err := DecodeHello(b); return err }},
		{"IHU", EncodeIHU(IHU{Interval: 100}), func(b []byte) error { _, _, err := DecodeIHU(b); return err }},
		{"RouterID", EncodeRouterID([8]byte{1}), func(b []byte) error { _, err := DecodeRouterID(b); return err }},
		{"NextHop", EncodeNextHop(net.ParseIP("fe80::1")), func(b []byte) error { _, err := DecodeNextHop(b); return err }},
		{"AckReq", EncodeAckReq(1, 100), func(b []byte) error { _, err := DecodeAckReq(b); return err }},
		{"RouteRequest", EncodeRouteRequest(RouteRequest{AE: AEIPv6, Prefix: prefix}), func(b []byte) error { _, err := DecodeRouteRequest(b); return err }},
		{"WildcardRequest", EncodeRouteRequest(RouteRequest{AE: AEWildcard}), func(b []byte) error { _, err := DecodeRouteRequest(b); return err }},
		{"SeqnoRequest", EncodeSeqnoRequest(SeqnoRequest{AE: AEIPv6, Prefix: prefix}), func(b []byte) error { _, err := DecodeSeqnoRequest(b); return err }},
	} {
		t.Run(test.name, func(t *testing.T) {
			if err := test.decode(test.tlv.Body); err != nil {
				t.Fatalf("valid TLV: %v", err)
			}
			if err := test.decode(append(append([]byte(nil), test.tlv.Body...), 0x7f, 0)); err != nil {
				t.Fatalf("optional extension was rejected: %v", err)
			}
			if err := test.decode(append(append([]byte(nil), test.tlv.Body...), 0xff, 0)); err == nil {
				t.Fatal("accepted an unknown mandatory extension")
			}
		})
	}
}
