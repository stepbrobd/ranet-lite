package ike

import "fmt"

// Minimal hand-rolled DER encoder — just enough to build the RDNSequence
// identity strongSwan expects (raw-pubkey "asn1dn:#hex" identities) and the
// RFC 7427 AlgorithmIdentifier for Ed25519. Not a general ASN.1 library.

func derLen(n int) []byte {
	if n < 128 {
		return []byte{byte(n)}
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte(n & 0xff)}, b...)
		n >>= 8
	}
	return append([]byte{0x80 | byte(len(b))}, b...)
}

func derTLV(tag byte, content []byte) []byte {
	out := make([]byte, 0, 2+len(content))
	out = append(out, tag)
	out = append(out, derLen(len(content))...)
	out = append(out, content...)
	return out
}

func derUTF8String(s string) []byte      { return derTLV(0x0c, []byte(s)) }
func derPrintableString(s string) []byte { return derTLV(0x13, []byte(s)) }
func derSequence(parts ...[]byte) []byte { return derTLV(0x30, concat(parts...)) }
func derSet(parts ...[]byte) []byte      { return derTLV(0x31, concat(parts...)) }

func concat(parts ...[]byte) []byte {
	var n int
	for _, p := range parts {
		n += len(p)
	}
	out := make([]byte, 0, n)
	for _, p := range parts {
		out = append(out, p...)
	}
	return out
}

// X.501 attribute type OIDs (RFC 4519), DER-encoded (tag+len+value).
var (
	oidOrganizationName = []byte{0x06, 0x03, 0x55, 0x04, 0x0a} // 2.5.4.10
	oidCommonName       = []byte{0x06, 0x03, 0x55, 0x04, 0x03} // 2.5.4.3
	oidSerialNumber     = []byte{0x06, 0x03, 0x55, 0x04, 0x05} // 2.5.4.5
)

// EncodeIdentityDN builds the DER RDNSequence ranet/strongSwan uses as a raw
// public key identity: RDNs {O=organization}, {CN=commonName},
// {serialNumber=serialNumber}, matching ranet's src/asn.rs byte for byte
// (O/CN as UTF8String, serialNumber as PrintableString).
func EncodeIdentityDN(organization, commonName, serialNumber string) []byte {
	atv := func(oid, value []byte) []byte { return derSequence(oid, value) }
	rdn := func(a []byte) []byte { return derSet(a) }
	return derSequence(
		rdn(atv(oidOrganizationName, derUTF8String(organization))),
		rdn(atv(oidCommonName, derUTF8String(commonName))),
		rdn(atv(oidSerialNumber, derPrintableString(serialNumber))),
	)
}

// Ed25519AlgorithmIdentifier is the DER SEQUENCE{OID} used both as the
// RFC 7427 signature AlgorithmIdentifier and inside a SubjectPublicKeyInfo;
// EdDSA (RFC 8410) carries no parameters.
func Ed25519AlgorithmIdentifier() []byte {
	return derSequence(OIDEd25519)
}

// derElement splits one DER TLV off the front of b and returns its tag, its
// content, and what follows. Only definite lengths appear in the structures
// this package reads, so an indefinite length is a decode error rather than
// something to interpret.
func derElement(b []byte) (tag byte, content, rest []byte, err error) {
	if len(b) < 2 {
		return 0, nil, nil, fmt.Errorf("ike: truncated DER element")
	}
	tag, b = b[0], b[1:]
	length := int(b[0])
	b = b[1:]
	if length&0x80 != 0 {
		count := length & 0x7f
		if count == 0 || count > 4 || len(b) < count {
			return 0, nil, nil, fmt.Errorf("ike: unsupported DER length")
		}
		// DER requires the shortest encoding: a long form below 128, or one
		// carrying a leading zero octet, is a second spelling of a length that
		// already has one. Accepting both makes two byte sequences decode to
		// the same name, and a peer's identity is the name this reads out.
		if b[0] == 0 {
			return 0, nil, nil, fmt.Errorf("ike: non-minimal DER length")
		}
		var value uint64
		for _, octet := range b[:count] {
			value = value<<8 | uint64(octet)
		}
		b = b[count:]
		if value < 128 {
			return 0, nil, nil, fmt.Errorf("ike: non-minimal DER length")
		}
		// Compared unsigned, against what is actually here, before it becomes
		// an int. Four length octets reach 4294967295, which as a 32 bit int
		// is negative: what caught that before was the minimality test above,
		// which is here for something else, so one certificate was refused as
		// a non-minimal length on a 32 bit build and as truncated content on a
		// 64 bit one. With the accumulator unsigned that test no longer sees
		// it at all, so this one keeps int(value) from going negative and the
		// slice below from panicking. Verified on a 386 build; see
		// TestDERLengthBeyondTheBufferIsRefusedNotSliced.
		if value > uint64(len(b)) {
			return 0, nil, nil, fmt.Errorf("ike: truncated DER content")
		}
		length = int(value)
	}
	if len(b) < length {
		return 0, nil, nil, fmt.Errorf("ike: truncated DER content")
	}
	return tag, b[:length], b[length:], nil
}

// derAttribute reads one single-valued RDN, SET{SEQUENCE{OID, value}}, and
// returns the attribute's OID and its string content.
//
// Both UTF8String and PrintableString are accepted for any attribute. ranet
// writes O and CN as UTF8String and the serial number as PrintableString,
// while strongSwan picks the type from the characters in the value, so the
// same name reaches the wire in either form. The name is not what
// authenticates a peer: AUTH signs the bytes actually received, so a
// re-encoded name still needs that peer's key to be accepted. Identities are
// compared as parsed names rather than as bytes, which makes that tolerance
// safe.
func derAttribute(rdn []byte) (oid []byte, value string, err error) {
	setTag, set, rest, err := derElement(rdn)
	if err != nil {
		return nil, "", err
	}
	if setTag != 0x31 || len(rest) != 0 {
		return nil, "", fmt.Errorf("ike: identity RDN is not a single SET")
	}
	seqTag, seq, rest, err := derElement(set)
	if err != nil {
		return nil, "", err
	}
	if seqTag != 0x30 || len(rest) != 0 {
		return nil, "", fmt.Errorf("ike: identity RDN does not hold exactly one attribute")
	}
	oid, _, seq, err = derElementRaw(seq)
	if err != nil {
		return nil, "", err
	}
	valueTag, content, rest, err := derElement(seq)
	if err != nil {
		return nil, "", err
	}
	if len(rest) != 0 {
		return nil, "", fmt.Errorf("ike: identity attribute has trailing data")
	}
	switch valueTag {
	case 0x0c, 0x13:
		return oid, string(content), nil
	default:
		return nil, "", fmt.Errorf("ike: identity attribute has string type %#x", valueTag)
	}
}

// derElementRaw is derElement, additionally returning the whole element
// including its tag and length, which is how an OID is compared.
func derElementRaw(b []byte) (raw, content, rest []byte, err error) {
	_, content, rest, err = derElement(b)
	if err != nil {
		return nil, nil, nil, err
	}
	return b[:len(b)-len(rest)], content, rest, nil
}

// DecodeIdentityDN reads the RDNSequence ranet and strongSwan use as a raw
// public key identity: exactly the three single-valued RDNs O, CN and
// serialNumber, in any order, each appearing once. A sequence with anything
// else in it is rejected rather than interpreted, because the name decides
// which key is allowed to verify AUTH.
func DecodeIdentityDN(b []byte) (organization, commonName, serialNumber string, err error) {
	tag, seq, rest, err := derElement(b)
	if err != nil {
		return "", "", "", err
	}
	if tag != 0x30 || len(rest) != 0 {
		return "", "", "", fmt.Errorf("ike: identity is not a single RDNSequence")
	}
	targets := []struct {
		oid   []byte
		value *string
		seen  bool
	}{
		{oid: oidOrganizationName, value: &organization},
		{oid: oidCommonName, value: &commonName},
		{oid: oidSerialNumber, value: &serialNumber},
	}
	count := 0
	for len(seq) != 0 {
		_, _, next, err := derElement(seq)
		if err != nil {
			return "", "", "", err
		}
		oid, value, err := derAttribute(seq[:len(seq)-len(next)])
		if err != nil {
			return "", "", "", err
		}
		matched := false
		for i := range targets {
			if !bytesEqual(oid, targets[i].oid) {
				continue
			}
			if targets[i].seen {
				return "", "", "", fmt.Errorf("ike: identity repeats an attribute")
			}
			targets[i].seen, matched = true, true
			*targets[i].value = value
		}
		if !matched {
			return "", "", "", fmt.Errorf("ike: identity carries an attribute type this profile does not use")
		}
		count++
		seq = next
	}
	if count != len(targets) {
		return "", "", "", fmt.Errorf("ike: identity has %d attributes, want %d", count, len(targets))
	}
	return organization, commonName, serialNumber, nil
}
