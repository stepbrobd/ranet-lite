package ike

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
)

// RekeyChild replaces the current Child SA without a new Diffie-Hellman
// exchange. Run must be active to service the serialized IKE request.
//
// The old inbound Child SA remains installed until the INFORMATIONAL Delete
// exchange acknowledges retirement.
func (s *Session) RekeyChild() error {
	return s.rekeyChild(false)
}

// RekeyChildProactively starts a packet-count-triggered Child-SA rekey. If a
// Child-SA rekey is already running, that exchange already satisfies the
// request and this method succeeds without starting a duplicate.
func (s *Session) RekeyChildProactively() error {
	return s.rekeyChild(true)
}

func (s *Session) rekeyChild(alreadyRunningIsSuccess bool) error {
	if !s.childRekeying.CompareAndSwap(false, true) {
		if alreadyRunningIsSuccess {
			return nil
		}
		return fmt.Errorf("ike: Child SA rekey already in progress")
	}
	defer s.childRekeying.Store(false)
	old := s.currentChild()
	if old.LocalSPI == 0 && old.RemoteSPI == 0 {
		return s.negotiateChild(nil)
	}
	if old.LocalSPI == 0 || old.RemoteSPI == 0 {
		return fmt.Errorf("ike: no Child SA to rekey")
	}
	err := s.negotiateChild(&old)
	var rejected *childNegotiationRejectedError
	if !errors.As(err, &rejected) || rejected.notify.Type != N_CHILD_SA_NOT_FOUND {
		return err
	}
	if rejected.notify.Protocol != ProtoESP || len(rejected.notify.SPI) != 4 || binary.BigEndian.Uint32(rejected.notify.SPI) != old.LocalSPI {
		return fmt.Errorf("ike: invalid CHILD_SA_NOT_FOUND response")
	}
	// The peer no longer has this SA, so no Delete exchange is possible.
	// RFC 7296 §2.25 recommends silently removing our stale half and creating
	// a new Child SA from scratch.
	if err := s.forgetChild(old); err != nil {
		return fmt.Errorf("ike: forget missing peer Child SA: %w", err)
	}
	return s.negotiateChild(nil)
}

func (s *Session) negotiateChild(old *ChildSA) error {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()
	context := s.currentContext()
	localSPI := randUint32Nonzero()
	for old != nil && localSPI == old.LocalSPI {
		localSPI = randUint32Nonzero()
	}
	spi := make([]byte, 4)
	binary.BigEndian.PutUint32(spi, localSPI)
	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		return fmt.Errorf("ike: generate Child SA rekey nonce: %w", err)
	}
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(spi)})},
		{Type: PayloadNonce, Body: EncodeNonce(nonce)},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	}
	var oldLocalSPI []byte
	if old != nil {
		oldLocalSPI = make([]byte, 4)
		binary.BigEndian.PutUint32(oldLocalSPI, old.LocalSPI)
		// REKEY_SA identifies the old SA by the SPI this exchange's
		// initiator expects in inbound ESP packets (RFC 7296 §1.3.3).
		inner = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: oldLocalSPI, Type: N_REKEY_SA})}}, inner...)
	}
	// Refused here rather than after the exchange. The peer installs the
	// replacement and switches its outbound SPI the moment it answers, so
	// proposing an SA this end cannot then install leaves the peer sending
	// into an SPI that was never registered, and every scheduled retry does
	// it again.
	if err := s.canReplaceChild(localSPI); err != nil {
		return err
	}
	response, err := s.requestOnLocked(context, CREATE_CHILD_SA, inner)
	if err != nil {
		return fmt.Errorf("ike: Child SA negotiation request: %w", err)
	}

	// The exchange completed, so RFC 7296 section 2.8 has the responder
	// holding a Child SA whatever this end then makes of the answer, and
	// RekeyChild retries on a capped backoff: every way out from here that is
	// not success has to tell the peer, or each attempt leaves one more
	// behind. The Delete names the SPI this end chose, because section 1.4.1
	// lists "the SPIs (as they would be expected in the headers of inbound
	// packets) of the SAs to be deleted" and those are the sender's own;
	// deleteChildren matches an arriving Delete against RemoteSPI to the same
	// rule. That SPI was drawn before the request went out, so even a response
	// this end cannot parse at all is one it can still withdraw from.
	orphaned := func(cause error) error {
		if _, delErr := s.requestLocked(INFORMATIONAL, []RawPayload{{Type: PayloadD,
			Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})}}); delErr != nil {
			slog.Warn("ike could not delete the Child SA a failed rekey left at the peer",
				"spi", localSPI, "err", delErr)
		}
		return cause
	}

	payloads, err := decodeChildNegotiationResponse(response, context.suite.PRFID)
	if err != nil {
		// A rejection is the one answer that installs nothing at the peer, and
		// rekeyChild reads it to recover from CHILD_SA_NOT_FOUND, so it passes
		// through whole.
		var rejected *childNegotiationRejectedError
		if errors.As(err, &rejected) {
			return err
		}
		return orphaned(err)
	}
	_, encr, remoteSPI, err := decodeChildProposal(payloads.sa.Body, old)
	if err != nil {
		return orphaned(fmt.Errorf("ike: invalid Child SA response proposal: %w", err))
	}
	if err := validateFullRangeSelectors(payloads.tsi, payloads.tsr); err != nil {
		return orphaned(err)
	}
	initKey, respKey, err := ChildSAKeymat(context.suite.PRFID, context.skD, nonce, payloads.nonce.Body, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return orphaned(err)
	}
	if err := s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits,
		LocalSPI: localSPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	}); err != nil {
		return orphaned(err)
	}
	if old == nil {
		return nil
	}
	deleted, err := s.requestLocked(INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{oldLocalSPI}})}})
	// The replacement is installed, so the old SA is finished whatever comes
	// back. Retire it on every path out of here. A response that names no SPI
	// at all is the case RFC 7296 section 1.4.1 requires of a peer whose own
	// Delete for this SA crossed ours ("the responses MUST NOT include Delete
	// payloads for the deleted SAs"), and a failed exchange leaves nobody to
	// send one. Leaving s.retiring set locks out every later rekey in both
	// directions for the life of the session, and the peer chooses when that
	// happens, so the inbound keys drain on the retirement timer instead.
	if retireErr := s.retireChild(old.RemoteSPI); retireErr != nil && err == nil {
		return retireErr
	}
	if err != nil {
		return fmt.Errorf("ike: retire replaced Child SA: %w", err)
	}
	for _, p := range deleted {
		if p.Type != PayloadD {
			continue
		}
		if _, err := DecodeDelete(p.Body); err != nil {
			return fmt.Errorf("ike: invalid Child SA retire response: %w", err)
		}
	}
	return nil
}

type childNegotiationRejectedError struct{ notify Notify }

func (e *childNegotiationRejectedError) Error() string {
	return fmt.Sprintf("ike: Child SA negotiation rejected: notify type %d", e.notify.Type)
}

func decodeChildNegotiationResponse(response []RawPayload, prfID uint16) (childExchangePayloads, error) {
	payloads, err := parseChildExchangePayloads(response)
	if err != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: invalid Child SA negotiation response: %w", err)
	}
	// An error response can consist solely of a Notify payload. Interpret the
	// authenticated error before requiring the SA, Nr, TSi, and TSr payloads
	// that RFC 7296 §§1.3.1 and 1.3.3 specify for a successful response.
	for _, notify := range payloads.notifies {
		if notify.Type < 16384 {
			return childExchangePayloads{}, &childNegotiationRejectedError{notify: notify}
		}
	}
	if err := validateCompleteChildExchange(payloads, prfID); err != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: invalid Child SA negotiation response: %w", err)
	}
	if payloads.ke != nil {
		return childExchangePayloads{}, fmt.Errorf("ike: Child SA response includes unrequested KE")
	}
	return payloads, nil
}

func (s *Session) handleChildRekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	s.stateMu.RLock()
	ikeBusy := ctx != s.current || s.localRekey != nil
	s.stateMu.RUnlock()
	if ikeBusy || s.retiringChild().LocalSPI != 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	var rekey Notify
	for _, payload := range inner {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		if notify.Type == N_REKEY_SA {
			rekey = notify
		}
	}
	child := s.currentChild()
	if rekey.Type != N_REKEY_SA && (child.LocalSPI != 0 || child.RemoteSPI != 0) {
		// Without REKEY_SA this requests a new Child SA. Reject it as an
		// additional SA only while this single-SA profile already has one;
		// after state loss, RFC 7296 §2.25 expects creation from scratch.
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_ADDITIONAL_SAS)
	}
	payloads, err := decodeChildExchangePayloads(inner, ctx.suite.PRFID)
	if err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var expected *ChildSA
	if rekey.Type == N_REKEY_SA {
		if s.childRekeying.Load() {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
		}
		if rekey.Protocol != ProtoESP || len(rekey.SPI) != 4 {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		if child.LocalSPI == 0 || binary.BigEndian.Uint32(rekey.SPI) != child.RemoteSPI {
			// RFC 7296 §2.25 requires CHILD_SA_NOT_FOUND to identify the
			// nonexistent SA by copying the Protocol ID and SPI from REKEY_SA.
			return s.responseNotifySA(ctx, msgID, CREATE_CHILD_SA, N_CHILD_SA_NOT_FOUND, rekey.Protocol, rekey.SPI)
		}
		// Checked before the Diffie-Hellman and the keymat, the work the
		// peer is really asking us to spend.
		if !s.allowPeerChildRekey() {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
		}
		expected = &child
	}
	if err := validateFullRangeSelectors(payloads.tsi, payloads.tsr); err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var group uint16
	var peerPublic []byte
	if payloads.ke != nil {
		group, peerPublic, err = DecodeKE(payloads.ke.Body)
		if err != nil || group == 0 {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
	}
	selected, err := selectChildRequestProposal(payloads.sa.Body, expected, group)
	if err != nil {
		var invalidKE *invalidKEError
		if errors.As(err, &invalidKE) {
			data := binary.BigEndian.AppendUint16(nil, invalidKE.group)
			return s.responseNotifyData(ctx, msgID, CREATE_CHILD_SA, N_INVALID_KE_PAYLOAD, data)
		}
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	// A local failure from here on answers TEMPORARY_FAILURE rather than
	// returning an error, which Run turns into a teardown of the IKE SA. RFC
	// 7296 section 1.3.1: "A failed attempt to create a Child SA SHOULD NOT
	// tear down the IKE SA: there is no reason to lose the work done to set up
	// the IKE SA."
	fail := func(err error) ([]byte, error) {
		slog.Warn("ike cannot answer a peer Child SA rekey", "err", err)
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	var sharedSecret, localPublic []byte
	if selected.dh.ID != 0 {
		dh, err := GenerateDH(selected.dh.ID)
		if err != nil {
			return fail(err)
		}
		sharedSecret, err = dh.SharedSecret(peerPublic)
		if err != nil {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		localPublic = dh.PublicBytes()
	}
	encr := selected.encryption
	var spi [4]byte
	for binary.BigEndian.Uint32(spi[:]) == 0 {
		if _, err := rand.Read(spi[:]); err != nil {
			return fail(err)
		}
	}
	nr := make([]byte, 32)
	if _, err := rand.Read(nr); err != nil {
		return fail(err)
	}
	initKey, respKey, err := childSAKeymat(ctx.suite.PRFID, ctx.skD, sharedSecret, payloads.nonce.Body, nr, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return fail(err)
	}
	replacement := ChildSA{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, LocalSPI: binary.BigEndian.Uint32(spi[:]), RemoteSPI: selected.remoteSPI, InboundKey: initKey, OutboundKey: respKey}
	if err := s.replaceChild(replacement); err != nil {
		return fail(err)
	}
	responseEncr := encr
	if responseEncr.ID == ENCR_CHACHA20_POLY1305 {
		// RFC 7296 §3.3.6 returns selected attributes unchanged; the fixed-key
		// ChaCha20-Poly1305 transform was offered without Key Length.
		responseEncr.KeyLengthBits = 0
	}
	response := Proposal{Number: selected.proposal.Number, Protocol: ProtoESP, SPI: spi[:], Transforms: []Transform{responseEncr, {Type: TransESN, ID: ESN_NO}}}
	// One transform of every type the offer carried, RFC 7296 section 2.7.
	if selected.integ.Type != 0 {
		response.Transforms = append(response.Transforms, selected.integ)
	}
	if selected.dh.Type != 0 {
		response.Transforms = append(response.Transforms, selected.dh)
	}
	responsePayloads := []RawPayload{{Type: PayloadSA, Body: EncodeSA([]Proposal{response})}, {Type: PayloadNonce, Body: EncodeNonce(nr)}}
	if localPublic != nil {
		responsePayloads = append(responsePayloads, RawPayload{Type: PayloadKE, Body: EncodeKE(selected.dh.ID, localPublic)})
	}
	responsePayloads = append(responsePayloads, RawPayload{Type: PayloadTSi, Body: payloads.tsi.Body}, RawPayload{Type: PayloadTSr, Body: payloads.tsr.Body})
	return s.response(ctx, msgID, CREATE_CHILD_SA, responsePayloads)
}
