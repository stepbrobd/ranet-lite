package ike

import (
	"encoding/binary"
	"errors"
	"os"
	"slices"
	"strings"
	"testing"
)

func encodedChildProposal(encryption Transform) []byte {
	return EncodeSA([]Proposal{{
		Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4},
		Transforms: []Transform{encryption, {Type: TransESN, ID: ESN_NO}},
	}})
}

func TestDecodeChildProposalNormalizesChaChaKeyLength(t *testing.T) {
	want := ChildSA{EncrID: ENCR_CHACHA20_POLY1305, EncrKeyBits: 256}
	_, got, _, err := decodeChildProposal(encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}), &want)
	if err != nil {
		t.Fatal(err)
	}
	if got.KeyLengthBits != 256 {
		t.Fatalf("key length normalized to %d, want 256", got.KeyLengthBits)
	}
	if _, _, _, err := decodeChildProposal(encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256}), &want); err == nil {
		t.Fatal("accepted Key Length attribute for fixed-length ChaCha20-Poly1305")
	}
}

func TestDecodeChildProposalRejectsInvalidShape(t *testing.T) {
	tests := []Proposal{
		{Number: 2, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}},
		{Number: 1, Protocol: ProtoIKE, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}},
		{Number: 1, Protocol: ProtoESP, SPI: []byte{0, 0, 0, 0}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}},
		{Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_YES}}},
		{Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192}, {Type: TransESN, ID: ESN_NO}}},
	}
	for _, proposal := range tests {
		if _, _, _, err := decodeChildProposal(EncodeSA([]Proposal{proposal}), nil); err == nil {
			t.Fatalf("accepted invalid proposal %+v", proposal)
		}
	}
}

func TestSelectChildRekeyProposalSkipsAttributedTransform(t *testing.T) {
	want := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
	proposal := Proposal{
		Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4},
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransESN, ID: ESN_NO},
		},
	}
	raw := addUnknownTVAttributeToFirstTransform(EncodeSA([]Proposal{proposal}))
	selection, err := selectChildRequestProposal(raw, &want, 0)
	if err != nil {
		t.Fatal(err)
	}
	selected := selection.encryption
	if selected.UnsupportedAttributes || selected.ID != want.EncrID || selected.KeyLengthBits != want.EncrKeyBits {
		t.Fatalf("selected transform = %#v", selected)
	}
}

func TestDecodeChildExchangePayloadsRejectsDuplicatesAndCriticalUnknowns(t *testing.T) {
	base := []RawPayload{
		{Type: PayloadSA, Body: encodedChildProposal(Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128})},
		{Type: PayloadNonce, Body: []byte{1}},
		{Type: PayloadTSi, Body: []byte{0, 0, 0, 0}},
		{Type: PayloadTSr, Body: []byte{0, 0, 0, 0}},
	}
	for _, extra := range []RawPayload{
		{Type: PayloadNonce, Body: []byte{2}},
		{Type: PayloadType(250), Critical: true},
	} {
		payloads := append(append([]RawPayload(nil), base...), extra)
		if _, err := decodeChildExchangePayloads(payloads, PRF_HMAC_SHA2_256); err == nil {
			t.Fatalf("accepted invalid extra payload %+v", extra)
		}
	}
}

func TestDecodeChildNegotiationResponseHandlesNotifyOnlyError(t *testing.T) {
	_, err := decodeChildNegotiationResponse([]RawPayload{{
		Type: PayloadN,
		Body: EncodeNotify(Notify{Type: N_TEMPORARY_FAILURE}),
	}}, PRF_HMAC_SHA2_256)
	if err == nil || !strings.Contains(err.Error(), "rejected: notify type 43") {
		t.Fatalf("notify-only response error = %v", err)
	}
}

func TestValidateFullRangeSelectors(t *testing.T) {
	want := fullRangeSelectors()
	if err := validateFullRangeSelectors(&RawPayload{Body: want}, &RawPayload{Body: want}); err != nil {
		t.Fatal(err)
	}
	narrow := EncodeTS([]TrafficSelector{FullRangeV4()})
	if err := validateFullRangeSelectors(&RawPayload{Body: narrow}, &RawPayload{Body: want}); err == nil {
		t.Fatal("accepted narrowed traffic selectors")
	}
}

// RFC 7296 section 2.10: a nonce "MUST be at least 128 bits in size, and MUST
// be at least half the key size of the negotiated pseudorandom function". The
// second half was missing, so a 16 byte nonce was taken under HMAC-SHA2-384,
// whose preferred key size is 48.
func TestNonceLengthFollowsTheNegotiatedPRF(t *testing.T) {
	for _, test := range []struct {
		prf    uint16
		length int
		want   bool
	}{
		{PRF_HMAC_SHA2_256, 15, false},
		{PRF_HMAC_SHA2_256, 16, true},
		{PRF_HMAC_SHA2_384, 16, false},
		{PRF_HMAC_SHA2_384, 23, false},
		{PRF_HMAC_SHA2_384, 24, true},
		{PRF_HMAC_SHA2_384, 257, false},
	} {
		if got := validNonceFor(make([]byte, test.length), test.prf); got != test.want {
			t.Errorf("a %d byte nonce under PRF %d was accepted=%v, want %v", test.length, test.prf, got, test.want)
		}
	}
}

// A peer that spells out INTEG NONE alongside an AEAD cipher does it on every
// proposal it sends, not only the IKE_SA_INIT one. Taking it there and
// refusing it on the Child SA bundled into IKE_AUTH kills the handshake one
// message after the exchange that was just made to work, and refusing it on an
// IKE rekey leaves such a peer established and unable to rekey from its own
// side. RFC 7296 section 2.7 then requires the answer to carry it back.
func TestIntegNoneIsTakenAndEchoedOnEveryProposal(t *testing.T) {
	integ := Transform{Type: TransInteg, ID: INTEG_NONE}
	esp := func(extra ...Transform) []byte {
		spi := []byte{0, 0, 0, 9}
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: append([]Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransESN, ID: ESN_NO},
		}, extra...)}})
	}
	selection, err := selectChildRequestProposal(esp(integ), nil, 0)
	if err != nil {
		t.Fatalf("a Child SA proposal naming INTEG NONE was refused: %v", err)
	}
	if selection.integ != integ {
		t.Errorf("the selection kept %+v, so the answer cannot carry it back", selection.integ)
	}
	// The other direction is not the same rule. decodeChildProposal reads the
	// answer to this end's own offer, which names no integrity transform, and
	// section 2.7 makes the answer a subset of the offer. See its own doc.
	if _, _, _, err := decodeChildProposal(esp(integ), nil); err == nil {
		t.Error("an answer to this end's offer named a transform type the offer did not")
	}

	// And an integrity transform there is no key for is still refused, because
	// every cipher this implementation offers is combined mode.
	unusable := Transform{Type: TransInteg, ID: 12}
	if _, err := selectChildRequestProposal(esp(unusable), nil, 0); err == nil {
		t.Error("a Child SA proposal naming a real integrity algorithm was accepted")
	}
	if _, _, _, err := decodeChildProposal(esp(unusable), nil); err == nil {
		t.Error("decoding a Child SA proposal naming a real integrity algorithm succeeded")
	}
}

// The Child SA selector draws the same line as the IKE one: RFC 7296 §3.3.6
// makes an integrity algorithm this end has no key for one unacceptable
// transform, and "other transforms with the same Transform Type are processed
// as usual", so an offer naming one alongside NONE still has an answer.
func TestUnusableChildIntegrityAlternativeDoesNotRefuseTheProposal(t *testing.T) {
	spi := []byte{0, 0, 0, 7}
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
	}
	none := Transform{Type: TransInteg, ID: INTEG_NONE}
	unusable := Transform{Type: TransInteg, ID: 12}

	body := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
		Transforms: append(slices.Clone(base), unusable, none)}})
	selection, err := selectChildRequestProposal(body, nil, 0)
	if err != nil {
		t.Fatalf("an offer naming an integrity algorithm alongside NONE was refused: %v", err)
	}
	if selection.integ != none {
		t.Errorf("the answer carries integrity transform %v, want the NONE the offer included", selection.integ)
	}

	onlyUnusable := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
		Transforms: append(slices.Clone(base), unusable)}})
	if _, err := selectChildRequestProposal(onlyUnusable, nil, 0); err == nil {
		t.Error("an offer whose every integrity alternative is unusable was accepted")
	}
	pair := EncodeSA([]Proposal{
		{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: append(slices.Clone(base), unusable)},
		{Number: 2, Protocol: ProtoESP, SPI: spi, Transforms: slices.Clone(base)},
	})
	if selection, err := selectChildRequestProposal(pair, nil, 0); err != nil || selection.proposal.Number != 2 {
		t.Errorf("the second proposal was not considered: %v, %v", selection.proposal.Number, err)
	}
}

// decodeChildProposal is the initiator reading the answer to its own offer,
// which is espProposal. RFC 7296 section 3.3.6 has it "check that the accepted
// offer is consistent with one of its proposals, and if not MUST terminate the
// exchange", and section 2.7 says consistent is "exactly one transform of each
// type included in the proposal". So a conforming answer carries the types
// espProposal carries, and an unoffered DH transform is the dangerous case:
// the responder would mean perfect forward secrecy, this end derives without
// it, and the Child SA it installs carries nothing.
func TestChildAnswerIsCheckedAgainstWhatThisEndOffered(t *testing.T) {
	spi := []byte{0, 0, 0, 9}
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
	}
	answer := func(extra ...Transform) []byte {
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
			Transforms: append(slices.Clone(base), extra...)}})
	}
	for name, extra := range map[string][]Transform{
		"the shape the offer asks for": nil,
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeChildProposal(answer(extra...), nil); err != nil {
				t.Errorf("a conforming answer was refused: %v", err)
			}
		})
	}
	for name, extra := range map[string][]Transform{
		"dh none":                  {{Type: TransDH, ID: 0}},
		"a real dh group":          {{Type: TransDH, ID: DH_CURVE25519}},
		"integ none spelled out":   {{Type: TransInteg, ID: INTEG_NONE}},
		"integ none with key bits": {{Type: TransInteg, ID: INTEG_NONE, KeyLengthBits: 128}},
		"dh and integ none":        {{Type: TransDH, ID: 0}, {Type: TransInteg, ID: INTEG_NONE}},
		"a repeated type":          {{Type: TransESN, ID: ESN_NO}},
		"an unknown type":          {{Type: TransformType(9), ID: 1}},
		"an integ algorithm":       {{Type: TransInteg, ID: 12}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, _, err := decodeChildProposal(answer(extra...), nil); err == nil {
				t.Error("an answer naming what the offer did not was accepted")
			}
		})
	}
}

// This is a drift guard on the offer, not a test of the reader: the reader
// knows two transform types, and a type added to espProposal has to be added
// to it in the same change, or every answer to the new offer is refused as
// inconsistent and no Child SA is ever established. Stated here rather than as
// a permissive default that would accept a value the reader does nothing
// with.
func TestEspProposalOffersNoTypeTheAnswerReaderRefuses(t *testing.T) {
	for _, transform := range espProposal([]byte{0, 0, 0, 1}).Transforms {
		switch transform.Type {
		case TransEncr, TransESN:
		default:
			t.Fatalf("espProposal offers transform type %d, which decodeChildProposal refuses: "+
				"an answer carries one transform of each type the offer included, RFC 7296 section 2.7",
				transform.Type)
		}
	}
}

// The responder answering somebody else's offer is the other direction, and it
// does echo a type it was offered: a peer that names DH or INTEG gets it back,
// RFC 7296 section 2.7. selectChildRequestProposal builds that, and it is not
// what decodeChildProposal above reads.
func TestResponderEchoesEveryTypeTheOfferNamed(t *testing.T) {
	spi := []byte{0, 0, 0, 9}
	base := []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
	}
	none := Transform{Type: TransInteg, ID: INTEG_NONE}
	for name, extra := range map[string][]Transform{
		"dh none":       {{Type: TransDH, ID: 0}},
		"pfs":           {{Type: TransDH, ID: DH_CURVE25519}},
		"integ none":    {none},
		"dh and integ":  {{Type: TransDH, ID: 0}, none},
		"pfs and integ": {{Type: TransDH, ID: DH_CURVE25519}, none},
	} {
		t.Run(name, func(t *testing.T) {
			offer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi,
				Transforms: append(slices.Clone(base), extra...)}})
			keGroup := uint16(0)
			for _, transform := range extra {
				if transform.Type == TransDH {
					keGroup = transform.ID
				}
			}
			selection, err := selectChildRequestProposal(offer, nil, keGroup)
			if err != nil {
				t.Fatalf("the offer was refused: %v", err)
			}
			child := responderChild{number: selection.proposal.Number,
				encryption: selection.encryption, dh: selection.dh, integ: selection.integ}
			for _, want := range extra {
				if !slices.Contains(child.proposal(spi).Transforms, want) {
					t.Errorf("the answer is %v, which drops %v", child.proposal(spi).Transforms, want)
				}
			}
		})
	}
}

// decodeChildProposal holds a rekey answer to the cipher the SA being replaced
// already uses, so the rekey offer has to ask for that one alone. Offering all
// three asks a question this end refuses the answer to: RFC 7296 section 2.7
// lets the responder take any transform in the proposal, and a peer whose
// preference order changed between the initial exchange and the rekey answers
// within the offer and is turned down.
func TestRekeyOffersOnlyTheCipherItsAnswerReaderWillTake(t *testing.T) {
	spi := []byte{0, 0, 0, 5}
	for _, old := range []ChildSA{
		{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 256},
		{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		{EncrID: ENCR_CHACHA20_POLY1305},
	} {
		offer := espRekeyProposal(spi, old)
		ciphers := 0
		for _, transform := range offer.Transforms {
			if transform.Type != TransEncr {
				continue
			}
			ciphers++
			if transform.ID != old.EncrID || transform.KeyLengthBits != old.EncrKeyBits {
				t.Errorf("the rekey offer names %v, which its own answer reader refuses", transform)
			}
		}
		if ciphers != 1 {
			t.Errorf("the rekey offer names %d ciphers, want the one the answer may carry", ciphers)
		}
		// Every answer a responder may build from that offer is one this end
		// reads, which is the property the two halves have to agree on.
		selection, err := selectChildRequestProposal(EncodeSA([]Proposal{offer}), nil, 0)
		if err != nil {
			t.Fatalf("the rekey offer was refused: %v", err)
		}
		child := responderChild{number: selection.proposal.Number,
			encryption: selection.encryption, dh: selection.dh, integ: selection.integ}
		if _, _, _, err := decodeChildProposal(EncodeSA([]Proposal{child.proposal(spi)}), &old); err != nil {
			t.Errorf("an answer built from the rekey offer was refused: %v", err)
		}
	}
	// The initial offer still names all three, because there is no old SA to
	// hold the answer to.
	ciphers := 0
	for _, transform := range espProposal(spi).Transforms {
		if transform.Type == TransEncr {
			ciphers++
		}
	}
	if ciphers != 3 {
		t.Errorf("the initial offer names %d ciphers, want every one this end has", ciphers)
	}
}

// RFC 7296 section 1.3 gives INVALID_KE_PAYLOAD "two octets of data
// associated with this notification: the accepted Diffie-Hellman group number
// in big endian order", and has the initiator retry in the group the responder
// gave. A notify without them tells a peer its group is wrong and not which
// one to use, so its retry is a guess. Every site that sends one has to carry
// them.
func TestEveryInvalidKENotifyNamesAGroup(t *testing.T) {
	// A Child SA offer whose DH group this end does not have, which draws
	// the notify from the selector all three sites read.
	spi := []byte{0, 0, 0, 3}
	offer := EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: spi, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
		{Type: TransESN, ID: ESN_NO},
		{Type: TransDH, ID: DH_CURVE25519},
	}}})
	_, err := selectChildRequestProposal(offer, nil, 0)
	var wrongGroup *invalidKEError
	if !errors.As(err, &wrongGroup) {
		t.Fatalf("an offer naming a group this end did not use reported %v", err)
	}
	if wrongGroup.group != DH_CURVE25519 {
		t.Errorf("the error names group %d, want the one the offer asked for", wrongGroup.group)
	}
	// And the data every site puts in the notify names it. All three build it
	// here, so this is the property rather than a sample of one site.
	notify, err := DecodeNotify(EncodeNotify(Notify{Type: N_INVALID_KE_PAYLOAD,
		Data: invalidKENotifyData(wrongGroup.group)}))
	if err != nil {
		t.Fatal(err)
	}
	if len(notify.Data) != 2 || binary.BigEndian.Uint16(notify.Data) != DH_CURVE25519 {
		t.Errorf("the notify carries %v, which no initiator can retry from", notify.Data)
	}
	// The initiator reads it back as the group to come back with.
	if group, ok := preferredGroupFromNotify(notify); !ok || group != DH_CURVE25519 {
		t.Errorf("an initiator reading that notify got %d, %v", group, ok)
	}
}

// preferredGroupFromNotify spells out what an initiator does with the data,
// so the two halves are checked against each other.
func preferredGroupFromNotify(n Notify) (uint16, bool) {
	if n.Type != N_INVALID_KE_PAYLOAD || len(n.Data) < 2 {
		return 0, false
	}
	return binary.BigEndian.Uint16(n.Data), true
}

// The property the test above asserts about the helper, asserted about the
// sites instead. Three of them answer with this notify and each builds the
// data separately, so a site that forgets it tells a peer its group is wrong
// and not which one to use, and that peer's retry is a guess. Reverting the
// third site alone left the suite green, which is how one of them came to be
// forgotten in the first place.
func TestEverySiteThatSendsInvalidKECarriesTheGroup(t *testing.T) {
	// Read out of the source rather than driven, because one of the three sits
	// inside completeResponderAuth and is reachable only through a whole
	// handshake. It holds that no site spells this notify without the data,
	// which the text requires.
	for _, name := range []string{"child_rekey.go", "ike_rekey.go", "responder.go"} {
		body, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(string(body), "\n")
		for i, line := range lines {
			if !strings.Contains(line, "N_INVALID_KE_PAYLOAD") || strings.Contains(line, "notify.Type") {
				continue
			}
			// The data is built on the same line or within the few after it,
			// where the notify is assembled.
			window := strings.Join(lines[max(0, i-4):min(len(lines), i+5)], "\n")
			if !strings.Contains(window, "invalidKENotifyData") && !strings.Contains(window, "group)") {
				t.Errorf("%s:%d sends INVALID_KE_PAYLOAD with no group: %s", name, i+1, strings.TrimSpace(line))
			}
		}
	}
}
