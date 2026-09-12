package babel

import (
	"encoding/binary"
	"fmt"
	"net"
	"net/netip"
)

// RouteRequest and SeqnoRequest may each carry a Source Prefix sub-TLV, which names the
// source-specific route table entry the request applies to (RFC 9079 sections
// 7.3 and 7.4). An invalid SourcePrefix is an ordinary request.
type RouteRequest struct {
	AE           uint8
	Prefix       netip.Prefix
	SourcePrefix netip.Prefix
}

func EncodeRouteRequest(r RouteRequest) RawTLV {
	if r.AE == AEWildcard || !r.Prefix.IsValid() {
		// A wildcard request must never carry a source prefix, RFC 9079 §7.3.
		return RawTLV{Type: TLVRouteRequest, Body: []byte{AEWildcard, 0}}
	}
	p := r.Prefix.Masked()
	raw := p.Addr().AsSlice()
	body := append([]byte{r.AE, byte(p.Bits())}, raw[:prefixByteLen(p.Bits())]...)
	if r.SourcePrefix.IsValid() {
		body = append(body, encodeSourcePrefix(r.AE, r.SourcePrefix)...)
	}
	return RawTLV{Type: TLVRouteRequest, Body: body}
}

func DecodeRouteRequest(body []byte) (RouteRequest, error) {
	if len(body) < 2 {
		return RouteRequest{}, fmt.Errorf("babel: short Route Request TLV")
	}
	prefix, source, err := decodeRequestPrefix(body[0], int(body[1]), body[2:])
	if err != nil {
		return RouteRequest{}, err
	}
	return RouteRequest{AE: body[0], Prefix: prefix, SourcePrefix: source}, nil
}

func decodeRequestPrefix(ae uint8, plen int, raw []byte) (prefix, source netip.Prefix, err error) {
	if ae == AEWildcard {
		if plen != 0 {
			return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("babel: wildcard request has nonzero prefix length")
		}
		// A wildcard request carrying a source prefix must be ignored, RFC 9079
		// section 5.2; the sub-TLV is mandatory, so an error is exactly that.
		_, err := decodeRequestSubTLVs(ae, raw)
		return netip.Prefix{}, netip.Prefix{}, err
	}
	bits := 128
	if ae == AEIPv4 || ae == AEIPv4ViaIPv6 {
		bits = 32
	} else if ae != AEIPv6 {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("babel: request has unsupported AE %d", ae)
	}
	if plen > bits || len(raw) < prefixByteLen(plen) {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("babel: malformed request prefix")
	}
	source, err = decodeRequestSubTLVs(ae, raw[prefixByteLen(plen):])
	if err != nil {
		return netip.Prefix{}, netip.Prefix{}, err
	}
	buf := make([]byte, bits/8)
	copy(buf, raw[:prefixByteLen(plen)])
	addr, _ := netip.AddrFromSlice(net.IP(buf))
	prefix = netip.PrefixFrom(addr.Unmap(), plen).Masked()
	// A v4-mapped address under AE 2 unmaps to IPv4 while its prefix length
	// still counts IPv6 bits, and a source prefix decoded under the same AE
	// stays sixteen bytes wide. Neither pair names a route.
	if !prefix.IsValid() {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("babel: request prefix length %d does not fit its address", plen)
	}
	if source.IsValid() && source.Addr().Is4() != prefix.Addr().Is4() {
		return netip.Prefix{}, netip.Prefix{}, fmt.Errorf("babel: request source prefix is from another address family")
	}
	return prefix, source, nil
}

// decodeRequestSubTLVs returns the source prefix of a source-specific request.
// Source Prefix is the only mandatory sub-TLV a request may carry: anything
// else, a second copy of it, or a malformed one invalidates the whole TLV
// (RFC 8966 section 4.4, RFC 9079 section 7).
func decodeRequestSubTLVs(ae uint8, raw []byte) (netip.Prefix, error) {
	subs, err := decodeSubTLVs(raw)
	if err != nil {
		return netip.Prefix{}, err
	}
	var source netip.Prefix
	for _, sub := range subs {
		if sub.Type < 128 {
			continue // non-mandatory: safe to skip if unrecognized
		}
		if sub.Type != SubTLVSourcePrefix {
			return netip.Prefix{}, fmt.Errorf("babel: unsupported mandatory sub-TLV %d", sub.Type)
		}
		if source.IsValid() {
			return netip.Prefix{}, fmt.Errorf("babel: request carries more than one source prefix")
		}
		decoded, ok := decodeSourcePrefix(ae, sub.Body)
		if !ok {
			return netip.Prefix{}, fmt.Errorf("babel: malformed source prefix sub-TLV")
		}
		source = decoded
	}
	return source, nil
}

type SeqnoRequest struct {
	AE           uint8
	Prefix       netip.Prefix
	SourcePrefix netip.Prefix
	Seqno        uint16
	HopCount     uint8
	RouterID     [8]byte
}

func EncodeSeqnoRequest(r SeqnoRequest) RawTLV {
	p := r.Prefix.Masked()
	raw := p.Addr().AsSlice()
	body := make([]byte, 14, 14+prefixByteLen(p.Bits()))
	body[0], body[1] = r.AE, byte(p.Bits())
	binary.BigEndian.PutUint16(body[2:4], r.Seqno)
	body[4] = r.HopCount
	copy(body[6:14], r.RouterID[:])
	body = append(body, raw[:prefixByteLen(p.Bits())]...)
	if r.SourcePrefix.IsValid() {
		body = append(body, encodeSourcePrefix(r.AE, r.SourcePrefix)...)
	}
	return RawTLV{Type: TLVSeqnoRequest, Body: body}
}

func DecodeSeqnoRequest(body []byte) (SeqnoRequest, error) {
	if len(body) < 14 {
		return SeqnoRequest{}, fmt.Errorf("babel: short Seqno Request TLV")
	}
	prefix, source, err := decodeRequestPrefix(body[0], int(body[1]), body[14:])
	if err != nil {
		return SeqnoRequest{}, fmt.Errorf("babel: malformed Seqno Request TLV: %w", err)
	}
	if !prefix.IsValid() {
		return SeqnoRequest{}, fmt.Errorf("babel: malformed Seqno Request TLV prefix")
	}
	r := SeqnoRequest{AE: body[0], Prefix: prefix, SourcePrefix: source,
		Seqno: binary.BigEndian.Uint16(body[2:4]), HopCount: body[4]}
	copy(r.RouterID[:], body[6:14])
	return r, nil
}
