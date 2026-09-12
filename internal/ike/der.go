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
		length = 0
		for _, octet := range b[:count] {
			length = length<<8 | int(octet)
		}
		b = b[count:]
		// DER requires the shortest encoding, so a long form below 128 or
		// with a leading zero octet is a different encoding of the same
		// value, which would break the byte-exact identity comparison.
		if length < 128 {
			return 0, nil, nil, fmt.Errorf("ike: non-minimal DER length")
		}
	}
	if len(b) < length {
		return 0, nil, nil, fmt.Errorf("ike: truncated DER content")
	}
	return tag, b[:length], b[length:], nil
}

// derAttribute reads one single-valued RDN, SET{SEQUENCE{OID, value}}, and
// returns the value's string content if the OID is the one expected.
func derAttribute(rdn []byte, oid []byte, tag byte) (string, error) {
	setTag, set, rest, err := derElement(rdn)
	if err != nil {
		return "", err
	}
	if setTag != 0x31 || len(rest) != 0 {
		return "", fmt.Errorf("ike: identity RDN is not a single SET")
	}
	seqTag, seq, rest, err := derElement(set)
	if err != nil {
		return "", err
	}
	if seqTag != 0x30 || len(rest) != 0 {
		return "", fmt.Errorf("ike: identity RDN holds %d attributes, want 1", 1+len(rest))
	}
	gotOID, _, seq, err := derElementRaw(seq)
	if err != nil {
		return "", err
	}
	if !bytesEqual(gotOID, oid) {
		return "", fmt.Errorf("ike: unexpected identity attribute type")
	}
	valueTag, value, rest, err := derElement(seq)
	if err != nil {
		return "", err
	}
	if valueTag != tag || len(rest) != 0 {
		return "", fmt.Errorf("ike: identity attribute has tag %#x, want %#x", valueTag, tag)
	}
	return string(value), nil
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

// DecodeIdentityDN parses exactly what EncodeIdentityDN produces: three
// single-valued RDNs in the order O, CN, serialNumber. Anything else is
// rejected rather than interpreted. The identity is the only thing binding an
// authenticated key to a named peer, so a caller re-encodes the result and
// compares it to the bytes on the wire before trusting it.
func DecodeIdentityDN(b []byte) (organization, commonName, serialNumber string, err error) {
	tag, seq, rest, err := derElement(b)
	if err != nil {
		return "", "", "", err
	}
	if tag != 0x30 || len(rest) != 0 {
		return "", "", "", fmt.Errorf("ike: identity is not a single RDNSequence")
	}
	fields := []struct {
		oid   []byte
		tag   byte
		value *string
	}{
		{oidOrganizationName, 0x0c, &organization},
		{oidCommonName, 0x0c, &commonName},
		{oidSerialNumber, 0x13, &serialNumber},
	}
	for _, field := range fields {
		_, _, next, err := derElement(seq)
		if err != nil {
			return "", "", "", err
		}
		*field.value, err = derAttribute(seq[:len(seq)-len(next)], field.oid, field.tag)
		if err != nil {
			return "", "", "", err
		}
		seq = next
	}
	if len(seq) != 0 {
		return "", "", "", fmt.Errorf("ike: identity has more than three RDNs")
	}
	return organization, commonName, serialNumber, nil
}
