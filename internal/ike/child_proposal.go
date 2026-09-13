package ike

import (
	"encoding/binary"
	"fmt"
	"slices"
)

func fullRangeSelectors() []byte {
	return EncodeTS([]TrafficSelector{FullRangeV4(), FullRangeV6()})
}

func validateFullRangeSelectors(tsi, tsr *RawPayload) error {
	if tsi == nil || tsr == nil {
		return fmt.Errorf("ike: Child SA exchange is missing traffic selectors")
	}
	if !isFullRangeSelectors(tsi.Body) {
		return fmt.Errorf("ike: unsupported initiator traffic selectors")
	}
	if !isFullRangeSelectors(tsr.Body) {
		return fmt.Errorf("ike: unsupported responder traffic selectors")
	}
	return nil
}

// Selector order and reserved bytes do not change the negotiated policy.
// Still require exactly one unrestricted selector for each address family.
func isFullRangeSelectors(body []byte) bool {
	selectors, err := DecodeTS(body)
	if err != nil || len(selectors) != 2 {
		return false
	}
	var v4, v6 bool
	for _, selector := range selectors {
		var expected TrafficSelector
		switch selector.Type {
		case TS_IPV4_ADDR_RANGE:
			if v4 {
				return false
			}
			v4, expected = true, FullRangeV4()
		case TS_IPV6_ADDR_RANGE:
			if v6 {
				return false
			}
			v6, expected = true, FullRangeV6()
		default:
			return false
		}
		// slices.Equal rather than net.IP.Equal: DecodeTS has already fixed the
		// width to the selector type, and net.IP.Equal would fold a 4-in-6
		// address onto its IPv4 form, which is a different selector on the
		// wire and must not compare equal to one.
		if selector.Protocol != 0 || selector.StartPort != 0 || selector.EndPort != 0xffff ||
			!slices.Equal(selector.StartAddr, expected.StartAddr) || !slices.Equal(selector.EndAddr, expected.EndAddr) {
			return false
		}
	}
	return v4 && v6
}

type childExchangePayloads struct {
	sa, nonce, ke, tsi, tsr *RawPayload
	notifies                []Notify
}

func decodeChildExchangePayloads(payloads []RawPayload, prfID uint16) (childExchangePayloads, error) {
	out, err := parseChildExchangePayloads(payloads)
	if err != nil {
		return childExchangePayloads{}, err
	}
	if err := validateCompleteChildExchange(out, prfID); err != nil {
		return childExchangePayloads{}, err
	}
	return out, nil
}

func parseChildExchangePayloads(payloads []RawPayload) (childExchangePayloads, error) {
	var out childExchangePayloads
	setUnique := func(dst **RawPayload, payload *RawPayload) error {
		if *dst != nil {
			return fmt.Errorf("ike: duplicate payload type %d in Child SA exchange", payload.Type)
		}
		*dst = payload
		return nil
	}
	for i := range payloads {
		payload := &payloads[i]
		var err error
		switch payload.Type {
		case PayloadSA:
			err = setUnique(&out.sa, payload)
		case PayloadNonce:
			err = setUnique(&out.nonce, payload)
		case PayloadTSi:
			err = setUnique(&out.tsi, payload)
		case PayloadTSr:
			err = setUnique(&out.tsr, payload)
		case PayloadN:
			notify, decodeErr := DecodeNotify(payload.Body)
			if decodeErr != nil {
				return childExchangePayloads{}, decodeErr
			}
			out.notifies = append(out.notifies, notify)
		case PayloadKE:
			err = setUnique(&out.ke, payload)
		default:
			if payload.Critical {
				return childExchangePayloads{}, fmt.Errorf("ike: unsupported critical payload type %d", payload.Type)
			}
		}
		if err != nil {
			return childExchangePayloads{}, err
		}
	}
	return out, nil
}

func validateCompleteChildExchange(payloads childExchangePayloads, prfID uint16) error {
	if payloads.sa == nil || payloads.nonce == nil || payloads.tsi == nil || payloads.tsr == nil ||
		!validNonceFor(payloads.nonce.Body, prfID) {
		return fmt.Errorf("ike: incomplete Child SA exchange")
	}
	return nil
}

// validNonce is RFC 7296 section 2.10 without its second half: "Nonces used in
// IKEv2 MUST be randomly chosen, MUST be at least 128 bits in size, and MUST
// be at least half the key size of the negotiated pseudorandom function." It
// is what the responder can check on an IKE_SA_INIT request, where the nonce
// arrives alongside the proposals the PRF is still to be chosen from.
func validNonce(nonce []byte) bool { return len(nonce) >= 16 && len(nonce) <= 256 }

// validNonceFor adds the second half, for every exchange whose PRF is settled.
// The PRFs here are HMAC constructions, whose preferred key size is their
// output size, so a 16 byte nonce is short for HMAC-SHA2-384.
func validNonceFor(nonce []byte, prfID uint16) bool {
	return validNonce(nonce) && len(nonce) >= PRFOutputLen(prfID)/2
}

func canonicalEncryptionTransform(t Transform) (Transform, error) {
	if t.Type != TransEncr {
		return Transform{}, fmt.Errorf("ike: expected an encryption transform")
	}
	if t.UnsupportedAttributes {
		return Transform{}, fmt.Errorf("ike: encryption transform has unsupported attributes")
	}
	if t.ID == ENCR_CHACHA20_POLY1305 && t.KeyLengthBits != 0 {
		return Transform{}, fmt.Errorf("ike: ChaCha20-Poly1305 has a fixed key length")
	}
	if _, err := aeadParams(t.ID, t.KeyLengthBits); err != nil {
		return Transform{}, err
	}
	if t.ID == ENCR_CHACHA20_POLY1305 {
		t.KeyLengthBits = 256
	}
	return t, nil
}

// decodeChildProposal validates the selected, single ESP proposal shared by
// IKE_AUTH and both CREATE_CHILD_SA directions.
func decodeChildProposal(body []byte, expected *ChildSA) (Proposal, Transform, uint32, error) {
	props, err := DecodeSA(body)
	if err != nil || len(props) != 1 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal")
	}
	p := props[0]
	// Two transforms decide keys, and a peer that spelled out INTEG NONE gets
	// it back, RFC 7296 section 2.7, so three is a shape this has to read.
	if p.Number != 1 || p.Protocol != ProtoESP || len(p.SPI) != 4 ||
		len(p.Transforms) < 2 || len(p.Transforms) > 3 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: invalid Child SA proposal shape")
	}
	remoteSPI := binary.BigEndian.Uint32(p.SPI)
	if remoteSPI == 0 {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has a zero SPI")
	}
	var encryption Transform
	var haveEncryption, haveESN bool
	for _, transform := range p.Transforms {
		switch transform.Type {
		case TransEncr:
			if haveEncryption {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has duplicate encryption transforms")
			}
			encryption, err = canonicalEncryptionTransform(transform)
			if err != nil {
				return Proposal{}, Transform{}, 0, err
			}
			haveEncryption = true
		case TransESN:
			if haveESN || transform.ID != ESN_NO || transform.KeyLengthBits != 0 || transform.UnsupportedAttributes {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has an unsupported ESN transform")
			}
			haveESN = true
		case TransInteg:
			// An AEAD cipher needs no integrity transform, and a peer naming
			// NONE says the same thing as omitting it. Refusing the spelling
			// would fail the Child SA bundled into IKE_AUTH for a peer whose
			// IKE_SA_INIT selectIKEProposal has just accepted.
			if transform.ID != INTEG_NONE || transform.KeyLengthBits != 0 || transform.UnsupportedAttributes {
				return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has an integrity transform")
			}
		default:
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal has transform type %d", transform.Type)
		}
	}
	if !haveEncryption || !haveESN {
		return Proposal{}, Transform{}, 0, fmt.Errorf("ike: incomplete Child SA proposal")
	}
	if expected != nil {
		wantBits := expected.EncrKeyBits
		if expected.EncrID == ENCR_CHACHA20_POLY1305 {
			wantBits = 0
		}
		want, err := canonicalEncryptionTransform(Transform{Type: TransEncr, ID: expected.EncrID, KeyLengthBits: wantBits})
		if err != nil || encryption.ID != want.ID || encryption.KeyLengthBits != want.KeyLengthBits {
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal changed encryption transform")
		}
	} else {
		matched := false
		for _, offered := range espProposal(nil).Transforms {
			if offered.Type != TransEncr {
				continue
			}
			canonical, err := canonicalEncryptionTransform(offered)
			if err == nil && canonical.ID == encryption.ID && canonical.KeyLengthBits == encryption.KeyLengthBits {
				matched = true
				break
			}
		}
		if !matched {
			return Proposal{}, Transform{}, 0, fmt.Errorf("ike: Child SA proposal selected an unoffered transform")
		}
	}
	return p, encryption, remoteSPI, nil
}

type childProposalSelection struct {
	proposal   Proposal
	encryption Transform
	dh         Transform
	// integ is the integrity transform the offer carried, or the zero value
	// when it carried none. RFC 7296 section 2.7 wants one transform of every
	// type the offer included back in the answer, and the only one this
	// implementation can take is NONE.
	integ     Transform
	remoteSPI uint32
}

type invalidKEError struct{ group uint16 }

func (e *invalidKEError) Error() string {
	return fmt.Sprintf("ike: peer must use DH group %d", e.group)
}

// Select an offered encryption suite and optional DH group. Unknown transform
// types reject the proposal, while unsupported alternatives of a known type
// are skipped (RFC 7296 §3.3.6).
func selectChildRequestProposal(body []byte, expected *ChildSA, keGroup uint16) (childProposalSelection, error) {
	props, err := DecodeSA(body)
	if err != nil {
		return childProposalSelection{}, fmt.Errorf("ike: invalid Child SA proposal")
	}
	var want *Transform
	if expected != nil {
		wantBits := expected.EncrKeyBits
		if expected.EncrID == ENCR_CHACHA20_POLY1305 {
			wantBits = 0
		}
		canonical, err := canonicalEncryptionTransform(Transform{Type: TransEncr, ID: expected.EncrID, KeyLengthBits: wantBits})
		if err != nil {
			return childProposalSelection{}, err
		}
		want = &canonical
	}
	var preferredDH uint16
	for _, p := range props {
		if p.Number == 0 || p.Protocol != ProtoESP || len(p.SPI) != 4 || binary.BigEndian.Uint32(p.SPI) == 0 {
			continue
		}
		var encryption, integ Transform
		var haveEncryption, haveESN, unacceptable bool
		for _, transform := range p.Transforms {
			switch transform.Type {
			case TransEncr:
				candidate, err := canonicalEncryptionTransform(transform)
				if err == nil && !haveEncryption && childEncryptionAccepted(candidate, want) {
					encryption = candidate
					haveEncryption = true
				}
			case TransESN:
				if !haveESN && transform.ID == ESN_NO && transform.KeyLengthBits == 0 && !transform.UnsupportedAttributes {
					haveESN = true
				}
			case TransDH:
				// Selected below after checking encryption and ESN.
			case TransInteg:
				// See decodeChildProposal: NONE alongside an AEAD cipher says
				// what omitting the transform says, and anything else is a
				// transform this implementation has no key for.
				if transform.ID != INTEG_NONE || transform.KeyLengthBits != 0 || transform.UnsupportedAttributes {
					unacceptable = true
					break
				}
				integ = transform
			default:
				unacceptable = true
			}
		}
		if !unacceptable && haveEncryption && haveESN {
			dh, preferred, ok := selectDHTransform(p.Transforms, keGroup, true)
			if ok {
				return childProposalSelection{p, encryption, dh, integ, binary.BigEndian.Uint32(p.SPI)}, nil
			}
			if preferredDH == 0 {
				preferredDH = preferred
			}
		}
	}
	if preferredDH != 0 {
		return childProposalSelection{}, &invalidKEError{preferredDH}
	}
	return childProposalSelection{}, fmt.Errorf("ike: no acceptable Child SA proposal")
}

func childEncryptionAccepted(candidate Transform, expected *Transform) bool {
	if expected != nil {
		return candidate.ID == expected.ID && candidate.KeyLengthBits == expected.KeyLengthBits
	}
	for _, offered := range espProposal(nil).Transforms {
		if offered.Type != TransEncr {
			continue
		}
		supported, err := canonicalEncryptionTransform(offered)
		if err == nil && candidate.ID == supported.ID && candidate.KeyLengthBits == supported.KeyLengthBits {
			return true
		}
	}
	return false
}

// Prefer an offered group matching KE. For Child SAs only, an omitted DH
// transform or explicit NONE permits deriving keys without a fresh exchange.
func selectDHTransform(transforms []Transform, keGroup uint16, optional bool) (Transform, uint16, bool) {
	var haveDH, haveNone bool
	for _, got := range transforms {
		if got.Type == TransDH {
			haveDH = true
			haveNone = haveNone || got == (Transform{Type: TransDH})
		}
	}
	var preferredDH, matchingDH Transform
	for _, want := range ikeProposal().Transforms {
		if want.Type != TransDH {
			continue
		}
		for _, got := range transforms {
			if got != want {
				continue
			}
			if preferredDH.Type == 0 {
				preferredDH = got
			}
			if got.ID == keGroup {
				matchingDH = got
			}
			break
		}
	}
	if matchingDH.Type != 0 {
		return matchingDH, preferredDH.ID, true
	}
	if optional {
		if !haveDH {
			return Transform{}, 0, true
		}
		if haveNone {
			return Transform{Type: TransDH}, 0, true
		}
	}
	return Transform{}, preferredDH.ID, false
}
