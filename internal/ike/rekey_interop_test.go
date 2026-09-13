package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"
)

func TestPeerChildRekeyWithPFS(t *testing.T) {
	for _, group := range []uint16{DH_CURVE25519, DH_ECP_256, DH_ECP_384} {
		for _, responder := range []bool{false, true} {
			t.Run(fmt.Sprintf("group=%d/responder=%t", group, responder), func(t *testing.T) {
				mux, _ := lifecycleMuxes(t)
				suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
				ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
					skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20), responder: responder}
				old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
				s := &Session{mux: mux, current: ctx, Child: old}
				dh, err := GenerateDH(group)
				if err != nil {
					t.Fatal(err)
				}
				ni := bytes.Repeat([]byte{4}, 32)
				proposal := espProposal(binary.BigEndian.AppendUint32(nil, 32))
				proposal.Transforms = append(proposal.Transforms, Transform{Type: TransDH, ID: group})
				raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
					{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
					{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
					{Type: PayloadNonce, Body: ni},
					{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
					{Type: PayloadTSi, Body: fullRangeSelectors()},
					{Type: PayloadTSr, Body: fullRangeSelectors()},
				})
				if err != nil {
					t.Fatal(err)
				}
				message, err := DecodeMessage(raw)
				if err != nil {
					t.Fatal(err)
				}
				inner, err := DecryptMessage(suite, ctx.localEncryptionKey(), raw, message)
				if err != nil {
					t.Fatal(err)
				}
				payloads, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256)
				if err != nil || payloads.ke == nil {
					t.Fatalf("invalid PFS response: %v, %v", inner, err)
				}
				gotGroup, public, err := DecodeKE(payloads.ke.Body)
				if err != nil || gotGroup != group {
					t.Fatalf("response KE group = %d, %v", gotGroup, err)
				}
				selected, err := DecodeSA(payloads.sa.Body)
				if err != nil || len(selected) != 1 {
					t.Fatalf("response proposal = %v, %v", selected, err)
				}
				var selectedDH uint16
				for _, transform := range selected[0].Transforms {
					if transform.Type == TransDH {
						selectedDH = transform.ID
					}
				}
				if selectedDH != group {
					t.Fatalf("selected DH group = %d, want %d", selectedDH, group)
				}
				shared, err := dh.SharedSecret(public)
				if err != nil {
					t.Fatal(err)
				}
				// Derive from the peer's DH secret, independently of the Child
				// helper. Keys follow the exchange initiator, not the IKE role.
				keymat := prfPlus(suite.PRFID, ctx.skD, concat(shared, ni, payloads.nonce.Body), 40)
				child := s.currentChild()
				if !bytes.Equal(child.InboundKey, keymat[:20]) || !bytes.Equal(child.OutboundKey, keymat[20:]) {
					t.Fatal("Child SA keys do not match peer PFS derivation")
				}
				if child.RemoteSPI != 32 || child.LocalSPI == old.LocalSPI || s.retiringChild().LocalSPI != old.LocalSPI {
					t.Fatal("Child SA overlap was not preserved")
				}
			})
		}
	}
}

func TestChildProposalDHSelection(t *testing.T) {
	for _, tc := range []struct {
		name       string
		groups     []uint16
		ke, want   uint16
		retryGroup uint16
	}{
		{"match KE", []uint16{DH_CURVE25519, DH_ECP_256}, DH_ECP_256, DH_ECP_256, 0},
		{"retry unsupported KE", []uint16{DH_ECP_256}, 14, 0, DH_ECP_256},
		{"retry missing KE", []uint16{DH_ECP_256}, 0, 0, DH_ECP_256},
		{"explicit NONE", []uint16{DH_ECP_256, 0}, 14, 0, 0},
		{"no PFS", nil, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			proposal := espProposal([]byte{1, 2, 3, 4})
			for _, group := range tc.groups {
				proposal.Transforms = append(proposal.Transforms, Transform{Type: TransDH, ID: group})
			}
			selected, err := selectChildRequestProposal(EncodeSA([]Proposal{proposal}), nil, tc.ke)
			if tc.retryGroup != 0 {
				var invalid *invalidKEError
				if !errors.As(err, &invalid) || invalid.group != tc.retryGroup {
					t.Fatalf("selection error = %v, want retry group %d", err, tc.retryGroup)
				}
			} else if err != nil || selected.dh.ID != tc.want {
				t.Fatalf("selected group = %d, %v; want %d", selected.dh.ID, err, tc.want)
			}
		})
	}
}

func TestIKERekeyProposalKeepsPRF(t *testing.T) {
	for _, prf := range []uint16{PRF_HMAC_SHA2_256, PRF_HMAC_SHA2_384} {
		proposal := ikeRekeyProposal(nil, prf)
		var count int
		for _, transform := range proposal.Transforms {
			if transform.Type == TransPRF {
				count++
				if transform.ID != prf {
					t.Fatalf("offered PRF %d, want %d", transform.ID, prf)
				}
			}
		}
		if count != 1 {
			t.Fatalf("offered %d PRFs, want 1", count)
		}
		_, suite, _, ok := selectIKERekeyProposal(ikeProposal(), DH_ECP_256, prf)
		if !ok || suite.PRFID != prf {
			t.Fatalf("selected PRF %d, want %d", suite.PRFID, prf)
		}
	}
}

func TestPeerRekeyDefersConflictingTransition(t *testing.T) {
	for _, state := range []string{"local Child rekey", "Child retirement", "local IKE rekey", "old IKE SA"} {
		t.Run(state, func(t *testing.T) {
			ctx := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}, skei: make([]byte, 20)}
			s := &Session{current: ctx}
			handle := s.handleIKERekey
			switch state {
			case "local Child rekey":
				s.childRekeying.Store(true)
			case "Child retirement":
				s.retiring.LocalSPI = 1
			case "local IKE rekey":
				s.localRekey = &ikeRekey{old: ctx}
				handle = s.handleChildRekey
			case "old IKE SA":
				s.current = new(ikeContext)
				handle = s.handleChildRekey
			}
			raw, err := handle(ctx, 0, nil)
			if err != nil {
				t.Fatal(err)
			}
			message, err := DecodeMessage(raw)
			if err != nil {
				t.Fatal(err)
			}
			inner, err := DecryptMessage(ctx.suite, ctx.skei, raw, message)
			if err != nil || len(inner) != 1 || inner[0].Type != PayloadN {
				t.Fatalf("response = %v, %v", inner, err)
			}
			notify, err := DecodeNotify(inner[0].Body)
			if err != nil || notify.Type != N_TEMPORARY_FAILURE {
				t.Fatalf("notify = %v, %v", notify, err)
			}
		})
	}
}

func TestQueuedChildRequestDoesNotUseRetiredIKE(t *testing.T) {
	s := &Session{current: new(ikeContext)}
	_, err := s.startRequest(&localRequest{exchange: CREATE_CHILD_SA, context: new(ikeContext)})
	if err == nil {
		t.Fatal("started CREATE_CHILD_SA on a replaced IKE SA")
	}
}

// The rate limit has to sit in handleChildRekey, before the Diffie-Hellman and
// the keymat, the work a peer rekeying in a loop is really asking us to
// spend.
func TestHandleChildRekeyRefusesSecondRekeyInSameInterval(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20)}
	old := ChildSA{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, LocalSPI: 21, RemoteSPI: 22}
	s := &Session{mux: mux, current: ctx, Child: old, started: time.Now()}

	rekey := func(msgID uint32, remoteSPI uint32) []RawPayload {
		raw, err := s.handleChildRekey(ctx, msgID, []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, remoteSPI)})},
			{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(binary.BigEndian.AppendUint32(nil, 32))})},
			{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
			{Type: PayloadTSi, Body: fullRangeSelectors()},
			{Type: PayloadTSr, Body: fullRangeSelectors()},
		})
		if err != nil {
			t.Fatal(err)
		}
		message, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(suite, ctx.localEncryptionKey(), raw, message)
		if err != nil {
			t.Fatal(err)
		}
		return inner
	}

	if notify := findType(rekey(0, old.RemoteSPI), PayloadN); notify != nil {
		decoded, _ := DecodeNotify(notify.Body)
		t.Fatalf("the first peer rekey was refused with notify type %d", decoded.Type)
	}
	// Clear the retirement the first rekey left outstanding, which would
	// refuse the second on its own and hide what this test is about.
	s.childMu.Lock()
	s.retiring = ChildSA{}
	s.childMu.Unlock()

	// The replacement is now current, so the second names it and is refused
	// only because it is too soon.
	next := s.currentChild()
	notify := findType(rekey(1, next.RemoteSPI), PayloadN)
	if notify == nil {
		t.Fatal("a second peer rekey in the same interval was accepted")
	}
	decoded, err := DecodeNotify(notify.Body)
	if err != nil || decoded.Type != N_TEMPORARY_FAILURE {
		t.Fatalf("second rekey answered with notify %v, %v, want TEMPORARY_FAILURE", decoded, err)
	}
}

// ChaCha20-Poly1305 carries no KEY_LENGTH attribute, and the CREATE_CHILD_SA
// response path has its own copy of the rule that suppresses it.
func TestChaChaChildRekeyResponseEchoesNoKeyLength(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: bytes.Repeat([]byte{1}, 32),
		skei: bytes.Repeat([]byte{2}, 20), sker: bytes.Repeat([]byte{3}, 20)}
	// A rekey keeps the cipher, so the SA being replaced has to be the one
	// whose response encoding is under test.
	old := ChildSA{EncrID: ENCR_CHACHA20_POLY1305, EncrKeyBits: 256, LocalSPI: 21, RemoteSPI: 22}
	s := &Session{mux: mux, current: ctx, Child: old, started: time.Now()}

	// Offered the way a conformant peer offers a fixed-key cipher: no Key
	// Length attribute at all.
	proposal := Proposal{
		Number: 1, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, 32),
		Transforms: []Transform{{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305}, {Type: TransESN, ID: ESN_NO}},
	}
	raw, err := s.handleChildRekey(ctx, 0, []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_REKEY_SA, Protocol: ProtoESP, SPI: binary.BigEndian.AppendUint32(nil, old.RemoteSPI)})},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{4}, 32)},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ctx.localEncryptionKey(), raw, message)
	if err != nil {
		t.Fatal(err)
	}
	payloads, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256)
	if err != nil {
		t.Fatalf("the rekey was refused rather than answered: %v, %v", inner, err)
	}
	selected, err := DecodeSA(payloads.sa.Body)
	if err != nil || len(selected) != 1 {
		t.Fatalf("response proposal = %v, %v", selected, err)
	}
	for _, transform := range selected[0].Transforms {
		if transform.Type == TransEncr && transform.KeyLengthBits != 0 {
			t.Errorf("the rekey response offered ChaCha20-Poly1305 with Key Length %d, which RFC 7296 section 3.3.5 forbids",
				transform.KeyLengthBits)
		}
	}
}
