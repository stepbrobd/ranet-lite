package babel

import (
	"encoding/binary"
	"fmt"
	"net"
)

// RouterID TLV, RFC 8966 §4.6.7: Reserved(2) + 8-byte Router-Id.
func EncodeRouterID(id [8]byte) RawTLV {
	body := make([]byte, 10)
	copy(body[2:], id[:])
	return RawTLV{Type: TLVRouterID, Body: body}
}

// DecodeRouterID also reports whether the TLV is otherwise to be ignored,
// which an unknown mandatory sub-TLV makes it. The router id is returned
// either way: RFC 8966 section 4.6.7 says "This TLV sets the router-id even if
// it is otherwise ignored due to an unknown mandatory sub-TLV", and section
// 4.5 says the same generally, that "parsing a TLV MUST update the parser
// state even if the TLV is otherwise ignored". Two nodes that disagree about
// which router id an Update belongs to keep different source-table entries for
// it, and neither one's feasibility distance then bounds the other.
func DecodeRouterID(body []byte) (id [8]byte, ignore bool, err error) {
	if len(body) < 10 {
		return id, false, fmt.Errorf("babel: short Router-Id TLV")
	}
	copy(id[:], body[2:10])
	if _, err := decodeOptionalSubTLVs(body[10:]); err != nil {
		return id, true, nil
	}
	return id, false, nil
}

// NextHop TLV, RFC 8966 §4.6.8.
func EncodeNextHop(addr net.IP) RawTLV {
	ae, a := encodeAddress(addr)
	body := make([]byte, 2+len(a))
	body[0] = ae
	copy(body[2:], a)
	return RawTLV{Type: TLVNextHop, Body: body}
}

func DecodeNextHop(body []byte) (net.IP, error) {
	if len(body) < 2 {
		return nil, fmt.Errorf("babel: short NextHop TLV")
	}
	addr, err := decodeAddress(body[0], body[2:])
	if err != nil {
		return nil, err
	}
	length := len(addr)
	if body[0] == AEIPv6LinkLocal {
		length = 8
	}
	if _, err := decodeOptionalSubTLVs(body[2+length:]); err != nil {
		return nil, err
	}
	return addr, nil
}

// AckReq / Ack, RFC 8966 §4.6.2/§4.6.3 — used for reliable signaling of
// e.g. link-down Updates. We answer AckReq (being unresponsive would make
// us a badly behaved peer) but don't originate AckReq ourselves in this
// minimal speaker.
func EncodeAckReq(nonce uint16, interval uint16) RawTLV {
	body := make([]byte, 6)
	binary.BigEndian.PutUint16(body[2:4], nonce)
	binary.BigEndian.PutUint16(body[4:6], interval)
	return RawTLV{Type: TLVAckReq, Body: body}
}

func DecodeAckReq(body []byte) (nonce uint16, err error) {
	if len(body) < 6 {
		return 0, fmt.Errorf("babel: short AckReq TLV")
	}
	if _, err := decodeOptionalSubTLVs(body[6:]); err != nil {
		return 0, err
	}
	return binary.BigEndian.Uint16(body[2:4]), nil
}

func EncodeAck(nonce uint16) RawTLV {
	body := make([]byte, 2)
	binary.BigEndian.PutUint16(body, nonce)
	return RawTLV{Type: TLVAck, Body: body}
}
