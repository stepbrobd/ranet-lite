package ike

import (
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
// side. RFC 7296 section 3.3 then requires the answer to carry it back.
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
	if _, _, _, err := decodeChildProposal(esp(integ), nil); err != nil {
		t.Errorf("decoding a Child SA proposal naming INTEG NONE failed: %v", err)
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
