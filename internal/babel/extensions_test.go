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

// A v4-mapped address under AE 2 unmaps to IPv4 while its prefix length still
// counts IPv6 bits. The result names no route, and once learned routes are
// re-advertised such an entry would leave as a malformed Update.
func TestMappedPrefixIsRejected(t *testing.T) {
	s, neighbor, _ := captureSpeaker(t, Config{})
	makeNeighborReachable(neighbor)
	mapped := netip.MustParseAddr("::ffff:10.0.0.0").As16()
	body := append([]byte{AEIPv6, updateFlagPrefix, 104, 0, 0, 200, 0, 1, 0, 64}, mapped[:13]...)
	body = append(body, SubTLVSourcePrefix, 14, 104)
	body = append(body, mapped[:13]...)
	s.handlePacket(neighbor, EncodePacket([]RawTLV{EncodeRouterID([8]byte{1}), {Type: TLVUpdate, Body: body}}))
	if got := len(s.routes.entries); got != 0 {
		t.Fatalf("a prefix length that does not fit its address created %d routes", got)
	}

	request := append([]byte{AEIPv6, 104}, mapped[:13]...)
	if _, err := DecodeRouteRequest(request); err == nil {
		t.Fatal("accepted a request for a prefix length that does not fit its address")
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

// RFC 8966 section 4.6.9: an Update's interval "MUST NOT be 0". Honoring one
// would expire the route in the pass that learned it, which collapses the
// section 3.5.4 hold that keeps a retracted prefix from following a covering
// route.
func TestUpdateWithZeroIntervalIsIgnored(t *testing.T) {
	dec := &PrefixDecoder{}
	body := EncodeUpdate(Update{AE: AEIPv6, Plen: 64, Interval: 0, Seqno: 1, Metric: 64,
		Prefix: net.ParseIP("fd00:1::")}).Body
	update, err := dec.Decode(body)
	if err != nil {
		t.Fatalf("decode: %v", err)
	}
	if !update.Ignore {
		t.Error("an Update asking for a zero interval was accepted")
	}

	// A retraction carries no interval that matters, so it is still honored.
	retraction := EncodeUpdate(Update{AE: AEIPv6, Plen: 64, Interval: 0, Seqno: 1,
		Metric: MetricInfinity, Prefix: net.ParseIP("fd00:1::")}).Body
	if update, err := dec.Decode(retraction); err != nil || update.Ignore {
		t.Errorf("a retraction was ignored (err %v)", err)
	}
}

// The RFC 9616 timestamps are read off a wall clock, so a step makes
// validTimestampGap reject every sample from then on. Without an expiry the
// neighbor keeps the last cost it computed for the life of the session, and
// nothing can correct it.
func TestRTTMeasurementThatStoppedArrivingStopsBeingUsed(t *testing.T) {
	s, neighbor, _ := captureSpeaker(t, Config{})
	now := time.Now()
	s.helloAction(neighbor, 2, now)
	ihu := EncodeIHU(IHU{RxCost: 32, Interval: 100, HasTS: true,
		OriginTS: uint32(now.Add(-50 * time.Millisecond).UnixMicro()), ReceiveTS: 1000})
	hello := EncodeHello(Hello{Seqno: 2, Interval: 100, HasTS: true, TxTS: 11_000})
	s.handlePacket(neighbor, EncodePacket([]RawTLV{hello, ihu}))
	if !neighbor.haveRTT {
		t.Fatal("a valid sample was discarded, so there is nothing here to expire")
	}

	// Still fresh well before the window is out.
	s.mu.Lock()
	s.sweepExpiredLocked(now.Add(time.Millisecond))
	s.mu.Unlock()
	if !neighbor.haveRTT {
		t.Error("a measurement that had just arrived was already treated as stale")
	}

	s.mu.Lock()
	s.sweepExpiredLocked(neighbor.rttExpiry.Add(time.Millisecond))
	s.mu.Unlock()
	if neighbor.haveRTT {
		t.Error("a measurement that stopped arriving is still costing this link")
	}
}
