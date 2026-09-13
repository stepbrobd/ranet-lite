package ike

import (
	"encoding/binary"
	"slices"
	"strconv"
	"strings"
	"testing"
)

func addUnknownTVAttributeToFirstTransform(raw []byte) []byte {
	transformOffset := 8 + int(raw[6])
	transformLength := int(binary.BigEndian.Uint16(raw[transformOffset+2 : transformOffset+4]))
	insertAt := transformOffset + transformLength
	unknown := []byte{0x80, 0x0f, 0, 1}
	withAttribute := make([]byte, 0, len(raw)+len(unknown))
	withAttribute = append(withAttribute, raw[:insertAt]...)
	withAttribute = append(withAttribute, unknown...)
	withAttribute = append(withAttribute, raw[insertAt:]...)
	binary.BigEndian.PutUint16(withAttribute[2:4], uint16(len(withAttribute)))
	binary.BigEndian.PutUint16(withAttribute[transformOffset+2:transformOffset+4], uint16(transformLength+len(unknown)))
	return withAttribute
}

func TestSuiteFromProposalRequiresExactOfferSelection(t *testing.T) {
	valid := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	if _, err := suiteFromProposal(valid); err != nil {
		t.Fatal(err)
	}
	for _, extra := range []Transform{
		{Type: TransInteg, ID: 12},
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192},
		{Type: TransformType(9), ID: 1},
	} {
		invalid := valid
		invalid.Transforms = append(append([]Transform(nil), valid.Transforms...), extra)
		if _, err := suiteFromProposal(invalid); err == nil {
			t.Fatalf("accepted invalid selected transform %+v", extra)
		}
	}
	// A responder that took an integrity transform this end offered has to
	// return it, RFC 7296 section 2.7, so the four-transform answer is a shape
	// this end has to read even though it never offers one. The three that
	// decide keys are still matched exactly.
	echoed := valid
	echoed.Transforms = append(append([]Transform(nil), valid.Transforms...), Transform{Type: TransInteg, ID: INTEG_NONE})
	if _, err := suiteFromProposal(echoed); err != nil {
		t.Errorf("an answer echoing INTEG NONE was refused: %v", err)
	}
}

func TestDecodeSARejectsInconsistentNestedFraming(t *testing.T) {
	valid := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}}}})
	for name, mutate := range map[string]func([]byte){
		"proposal marker":  func(raw []byte) { raw[0] = 1 },
		"transform marker": func(raw []byte) { raw[8] = 1 },
		"transform count":  func(raw []byte) { raw[7] = 2 },
		"trailing data":    func(raw []byte) { raw[0] = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), valid...)
			if name == "trailing data" {
				raw = append(raw, 0)
			} else {
				mutate(raw)
			}
			if _, err := DecodeSA(raw); err == nil {
				t.Fatal("DecodeSA accepted inconsistent framing")
			}
		})
	}
}

func TestUnknownTransformAttributeMakesOnlyTransformUnacceptable(t *testing.T) {
	proposal := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	withAttribute := addUnknownTVAttributeToFirstTransform(EncodeSA([]Proposal{proposal}))

	decoded, err := DecodeSA(withAttribute)
	if err != nil {
		t.Fatal(err)
	}
	if !decoded[0].Transforms[0].UnsupportedAttributes {
		t.Fatal("unknown attribute was silently discarded")
	}
	selected, suite, _, ok := selectIKERekeyProposal(decoded[0], DH_CURVE25519, PRF_HMAC_SHA2_256)
	if !ok || suite.EncrKeyBits != 128 || selected[0].KeyLengthBits != 128 {
		t.Fatalf("selection did not skip attributed transform: selected=%#v suite=%#v", selected, suite)
	}

	selectedResponse := decoded[0]
	selectedResponse.Transforms = []Transform{decoded[0].Transforms[0], decoded[0].Transforms[2], decoded[0].Transforms[3]}
	if _, err := suiteFromProposal(selectedResponse); err == nil {
		t.Fatal("initiator accepted selected transform with unknown attribute")
	}
}

func TestIKERekeyProposalRejectsUnexpectedTransformType(t *testing.T) {
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}
	unknown := Proposal{Number: 1, Protocol: ProtoIKE,
		Transforms: append(slices.Clone(base), Transform{Type: TransformType(9), ID: 1})}
	if _, _, _, ok := selectIKERekeyProposal(unknown, DH_CURVE25519, PRF_HMAC_SHA2_256); ok {
		t.Fatal("accepted IKE rekey proposal with unexpected transform type")
	}
	// An integrity transform this implementation has no key for is refused the
	// same way, because every cipher it offers is combined mode.
	unusable := Proposal{Number: 1, Protocol: ProtoIKE,
		Transforms: append(slices.Clone(base), Transform{Type: TransInteg, ID: 12})}
	if _, _, _, ok := selectIKERekeyProposal(unusable, DH_CURVE25519, PRF_HMAC_SHA2_256); ok {
		t.Fatal("accepted an integrity transform there is no key for")
	}
	// INTEG NONE says what omitting the transform says, and selectIKEProposal
	// takes it on the initial exchange, so refusing it here would leave such a
	// peer established and unable to rekey from its own side. RFC 7296 section
	// 2.7 then has the answer carry it: "The accepted cryptographic suite MUST
	// contain exactly one transform of each type included in the proposal."
	integ := Transform{Type: TransInteg, ID: INTEG_NONE}
	none := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: append(slices.Clone(base), integ)}
	selected, _, _, ok := selectIKERekeyProposal(none, DH_CURVE25519, PRF_HMAC_SHA2_256)
	if !ok {
		t.Fatal("a rekey proposal naming INTEG NONE was refused")
	}
	if !slices.Contains(selected, integ) {
		t.Errorf("the answer is %v, which drops a transform type the offer included", selected)
	}
}

func TestSupportsIdentitySignatureHash(t *testing.T) {
	identity := make([]byte, 2)
	binary.BigEndian.PutUint16(identity, HashIdentity)
	payloads := []RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: identity})}}
	if ok, err := supportsSignatureHash(payloads, HashIdentity); err != nil || !ok {
		t.Fatalf("identity support = %v, %v", ok, err)
	}
	if ok, err := supportsSignatureHash(nil, HashIdentity); err != nil || ok {
		t.Fatalf("missing notification = %v, %v", ok, err)
	}
}

// A rekey has to converge on one Diffie-Hellman group when both ends propose
// at once, and it does that by ranking candidates the same way at both ends:
// by this node's own offer order, which is identical on every node running
// this code. A ranking that did not follow the offer would make two nodes
// prefer different groups and neither exchange would complete.
func TestIKEGroupPreferenceFollowsOfferOrder(t *testing.T) {
	var groups []uint16
	for _, transform := range ikeProposal().Transforms {
		if transform.Type == TransDH {
			groups = append(groups, transform.ID)
		}
	}
	if len(groups) < 2 {
		t.Fatalf("only %d groups are offered, so there is no order to follow", len(groups))
	}
	for i, group := range groups {
		if got := ikeGroupPreference(group); got != i {
			t.Errorf("group %d ranks %d, want %d, its place in what we offer", group, got, i)
		}
	}
	// Anything we do not offer ranks behind everything we do, so a group we
	// cannot generate is never the one picked.
	if got, last := ikeGroupPreference(1), ikeGroupPreference(groups[len(groups)-1]); got <= last {
		t.Errorf("a group we do not offer ranks %d, ahead of or level with our last at %d", got, last)
	}
}

// The error is what tells the peer which group to come back with, so it has to
// name it.
func TestInvalidKEErrorNamesGroup(t *testing.T) {
	message := (&invalidKEError{group: DH_CURVE25519}).Error()
	if !strings.Contains(message, strconv.Itoa(int(DH_CURVE25519))) {
		t.Errorf("the error reads %q and does not name group %d", message, DH_CURVE25519)
	}
}
