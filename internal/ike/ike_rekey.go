package ike

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
)

// RekeyIKE replaces the IKE SA while retaining the current Child SAs. Run
// must be active to service the serialized IKE requests.
func (s *Session) RekeyIKE() error {
	s.requestMu.Lock()
	defer s.requestMu.Unlock()

	old := s.currentContext()
	spiI := randUint64Nonzero()
	for spiI == old.spiI {
		spiI = randUint64Nonzero()
	}
	group := uint16(DH_CURVE25519)
	ni := make([]byte, 32)
	if err := s.fillIKERekeyNonce(ni); err != nil {
		return fmt.Errorf("ike: generate IKE SA rekey nonce: %w", err)
	}
	s.stateMu.Lock()
	s.localRekey = &ikeRekey{old: old, nonce: ni}
	s.stateMu.Unlock()
	defer func() {
		s.stateMu.Lock()
		defer s.stateMu.Unlock()
		if s.localRekey != nil && s.localRekey.old == old {
			s.localRekey = nil
		}
	}()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiI)
	proposal := ikeRekeyProposal(spi, old.suite.PRFID)
	var (
		dh       *DHKeyPair
		response []RawPayload
		err      error
	)
	for attempt := 0; attempt < 2; attempt++ {
		dh, err = GenerateDH(group)
		if err != nil {
			return fmt.Errorf("ike: generate IKE SA rekey DH key: %w", err)
		}
		response, err = s.requestLocked(CREATE_CHILD_SA, []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
		})
		if err != nil {
			return fmt.Errorf("ike: IKE SA rekey request: %w", err)
		}

		var retryGroup uint16
		for i := range response {
			if response[i].Type != PayloadN {
				continue
			}
			notify, err := DecodeNotify(response[i].Body)
			if err != nil {
				return fmt.Errorf("ike: invalid IKE SA rekey notify: %w", err)
			}
			if notify.Type != N_INVALID_KE_PAYLOAD {
				continue
			}
			if len(notify.Data) != 2 {
				return fmt.Errorf("ike: invalid IKE SA rekey INVALID_KE_PAYLOAD data")
			}
			retryGroup = binary.BigEndian.Uint16(notify.Data)
			break
		}
		if retryGroup == 0 {
			break
		}
		if attempt != 0 || !supportedIKEGroup(retryGroup) {
			return fmt.Errorf("ike: IKE SA rekey rejected: requested unsupported DH group %d", retryGroup)
		}
		// RFC 7296 §1.3 permits the responder to select another offered DH
		// group with INVALID_KE_PAYLOAD. Retry as a new CREATE_CHILD_SA
		// exchange, using the requested group in both SA and KE processing.
		group = retryGroup
	}

	var sa, nonce, ke *RawPayload
	for i := range response {
		switch response[i].Type {
		case PayloadN:
			n, err := DecodeNotify(response[i].Body)
			if err != nil {
				return fmt.Errorf("ike: invalid IKE SA rekey notify: %w", err)
			}
			if n.Type < 16384 {
				return fmt.Errorf("ike: IKE SA rekey rejected: notify type %d", n.Type)
			}
		case PayloadSA:
			sa = &response[i]
		case PayloadNonce:
			nonce = &response[i]
		case PayloadKE:
			ke = &response[i]
		}
	}
	if sa == nil || nonce == nil || ke == nil {
		return fmt.Errorf("ike: incomplete IKE SA rekey response")
	}
	props, err := DecodeSA(sa.Body)
	// The answer to this end's own rekey offer, which names three transform
	// types, so section 2.7 has it carry three. suiteFromProposal checks the
	// rest of the consistency section 3.3.6 requires.
	if err != nil || len(props) != 1 || props[0].Number != 1 || props[0].Protocol != ProtoIKE ||
		len(props[0].SPI) != 8 || len(props[0].Transforms) != 3 {
		return fmt.Errorf("ike: invalid IKE SA rekey proposal")
	}
	selectedProposal := props[0]
	selectedProposal.SPI = nil
	suite, err := suiteFromProposal(selectedProposal)
	if err != nil {
		return fmt.Errorf("ike: invalid IKE SA rekey transforms: %w", err)
	}
	if suite.DHGroup != group {
		return fmt.Errorf("ike: IKE SA rekey chose DH group %d, want %d", suite.DHGroup, group)
	}
	// Checked here rather than with the other payloads, because half the rule
	// is the key size of the PRF this proposal just settled.
	if !validNonceFor(nonce.Body, suite.PRFID) {
		return fmt.Errorf("ike: IKE SA rekey nonce length %d is short for the negotiated PRF", len(nonce.Body))
	}
	for _, selected := range props[0].Transforms {
		matched := false
		for _, offered := range proposal.Transforms {
			if selected == offered {
				matched = true
				break
			}
		}
		if !matched {
			return fmt.Errorf("ike: IKE SA rekey chose unsupported transform %d/%d", selected.Type, selected.ID)
		}
	}
	spiR := binary.BigEndian.Uint64(props[0].SPI)
	if spiR == 0 {
		return fmt.Errorf("ike: IKE SA rekey returned zero SPI")
	}
	peerGroup, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || peerGroup != group {
		return fmt.Errorf("ike: IKE SA rekey KE group mismatch (got %d, used %d)", peerGroup, group)
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return fmt.Errorf("ike: IKE SA rekey shared secret: %w", err)
	}
	keys, err := DeriveRekeyedIKEKeys(old.suite.PRFID, old.skD, suite, shared, ni, nonce.Body, spiI, spiR)
	if err != nil {
		return fmt.Errorf("ike: derive IKE SA rekey keys: %w", err)
	}
	newContext := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR}
	s.stateMu.RLock()
	collision := s.collision
	localRekey := s.localRekey
	s.stateMu.RUnlock()
	if collision != nil {
		localLoses := lowestNonceBelongsToFirst(ni, nonce.Body, localRekey.peerNonce, localRekey.peerResponseNonce)
		if localLoses {
			slog.Info("ike simultaneous rekey selected peer candidate")
			if err := s.mux.RegisterIKE(spiI); err != nil {
				return fmt.Errorf("ike: register redundant IKE SA: %w", err)
			}
			// Both the winner and the redundant context must remain visible
			// to dispatch while the Delete exchange is outstanding.
			s.stateMu.Lock()
			s.retainOldLocked(old)
			s.current = collision
			s.retainCollisionLocked(newContext)
			s.stateMu.Unlock()
			// The redundant SA goes whether or not the peer answers. Leaving
			// it in s.collision refuses every later peer rekey, and the next
			// local one takes this branch again with no peer nonce, so the
			// failure would be permanent rather than one lost exchange.
			deleteErr := func() error {
				_, err := s.requestOnLocked(newContext, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
				return err
			}()
			s.mux.UnregisterIKE(spiI)
			s.stateMu.Lock()
			if s.collision == newContext {
				s.collision = nil
			}
			s.stateMu.Unlock()
			if deleteErr != nil {
				return fmt.Errorf("ike: delete redundant local IKE SA: %w", deleteErr)
			}
			return nil
		}
		// The redundant SA is the one the peer created, and RFC 7296 section
		// 2.8.2 leaves it to its creator: "The new IKE SA containing the
		// lowest nonce SHOULD be deleted by the node that created it." This
		// end deleting it too put two Deletes on the wire at once. The peer's
		// arrives first, because it was sent before ours could have reached
		// it, and answering it retires the SA our own Delete is outstanding
		// on, so that exchange fails with contextRetired and RekeyIKE returns
		// before registering the winning SA: the peer holds the new SA as
		// current, this end never does, and the session dies of unanswered
		// liveness checks. It stays registered so the peer's Delete can be
		// answered, and expireRetainedContexts gives up on a Delete that
		// never comes.
		slog.Info("ike simultaneous rekey selected local candidate")
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		return fmt.Errorf("ike: register rekeyed IKE SA: %w", err)
	}
	s.stateMu.Lock()
	s.retainOldLocked(old)
	s.current = newContext
	s.stateMu.Unlock()

	if _, err := s.requestOnLocked(old, INFORMATIONAL, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}); err != nil {
		return fmt.Errorf("ike: retire replaced IKE SA: %w", err)
	}
	s.mux.UnregisterIKE(old.spiI)
	s.stateMu.Lock()
	if s.old == old {
		s.old = nil
	}
	s.stateMu.Unlock()
	return nil
}

// handleIKERekey accepts a peer-initiated IKE SA rekey. Its response remains
// protected by ctx; the newly-derived context becomes current for subsequent
// exchanges while ctx stays available until the peer deletes it.
func (s *Session) handleIKERekey(ctx *ikeContext, msgID uint32, inner []RawPayload) ([]byte, error) {
	s.stateMu.RLock()
	accept := ctx == s.current && (s.old == nil || s.localRekey != nil) && s.collision == nil
	s.stateMu.RUnlock()
	if !accept || s.childRekeying.Load() || s.retiringChild().LocalSPI != 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_TEMPORARY_FAILURE)
	}
	var sa, nonce, ke *RawPayload
	for i := range inner {
		switch inner[i].Type {
		case PayloadSA:
			if sa != nil {
				return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
			}
			sa = &inner[i]
		case PayloadNonce:
			if nonce != nil {
				return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
			}
			nonce = &inner[i]
		case PayloadKE:
			if ke != nil {
				return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
			}
			ke = &inner[i]
		case PayloadTSi, PayloadTSr:
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
	}
	if sa == nil || nonce == nil || ke == nil || !validNonce(nonce.Body) {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	// The rest of RFC 7296 section 2.10 needs the PRF, which the proposal
	// below settles; see the second check after suiteFromProposal.
	props, err := DecodeSA(sa.Body)
	if err != nil || len(props) == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	group, peerPublic, err := DecodeKE(ke.Body)
	if err != nil || len(peerPublic) == 0 {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	var (
		selected         []Transform
		suite            SASuite
		selectedProposal Proposal
		preferredGroup   uint16
	)
	for _, proposal := range props {
		if proposal.Number == 0 || proposal.Protocol != ProtoIKE || len(proposal.SPI) != 8 || binary.BigEndian.Uint64(proposal.SPI) == 0 {
			continue
		}
		candidate, candidateSuite, candidatePreferred, ok := selectIKERekeyProposal(proposal, group, ctx.suite.PRFID)
		if ok {
			selected = candidate
			suite = candidateSuite
			selectedProposal = proposal
			break
		}
		if candidatePreferred != 0 && (preferredGroup == 0 || ikeGroupPreference(candidatePreferred) < ikeGroupPreference(preferredGroup)) {
			preferredGroup = candidatePreferred
		}
	}
	if selected == nil {
		if preferredGroup == 0 {
			return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
		}
		data := make([]byte, 2)
		binary.BigEndian.PutUint16(data, preferredGroup)
		// RFC 7296 §1.3 requires INVALID_KE_PAYLOAD, carrying the
		// preferred group, when a proposal is acceptable but its KE payload
		// uses a different group.
		return s.responseNotifyData(ctx, msgID, CREATE_CHILD_SA, N_INVALID_KE_PAYLOAD, data)
	}
	// The PRF is settled now, so the rest of RFC 7296 section 2.10 can be
	// applied to the nonce that arrived with the proposal.
	if !validNonceFor(nonce.Body, suite.PRFID) {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	spiI := binary.BigEndian.Uint64(selectedProposal.SPI)
	dh, err := GenerateDH(group)
	if err != nil {
		return nil, fmt.Errorf("ike: generate peer IKE rekey DH key: %w", err)
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return s.responseNotify(ctx, msgID, CREATE_CHILD_SA, N_NO_PROPOSAL_CHOSEN)
	}
	nr := make([]byte, 32)
	if err := s.fillIKERekeyNonce(nr); err != nil {
		return nil, fmt.Errorf("ike: generate peer IKE rekey nonce: %w", err)
	}
	spiR := randUint64Nonzero()
	keys, err := DeriveRekeyedIKEKeys(ctx.suite.PRFID, ctx.skD, suite, shared, nonce.Body, nr, spiI, spiR)
	if err != nil {
		return nil, fmt.Errorf("ike: derive peer IKE rekey keys: %w", err)
	}
	if err := s.mux.RegisterIKE(spiI); err != nil {
		return nil, fmt.Errorf("ike: register peer rekeyed IKE SA: %w", err)
	}
	newContext := &ikeContext{suite: suite, skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr, spiI: spiI, spiR: spiR, responder: true}
	s.stateMu.Lock()
	local := s.localRekey
	if local != nil && local.old == ctx {
		local.peerNonce = append([]byte(nil), nonce.Body...)
		local.peerResponseNonce = append([]byte(nil), nr...)
		s.retainCollisionLocked(newContext)
	} else {
		s.retainOldLocked(ctx)
		s.current = newContext
	}
	s.stateMu.Unlock()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, spiR)
	response := Proposal{Number: selectedProposal.Number, Protocol: ProtoIKE, SPI: spi, Transforms: selected}
	return s.response(ctx, msgID, CREATE_CHILD_SA, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{response})},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
	})
}

func (s *Session) fillIKERekeyNonce(nonce []byte) error {
	if s.ikeRekeyNonce != nil {
		return s.ikeRekeyNonce(nonce)
	}
	_, err := rand.Read(nonce)
	return err
}

// compareIKENonces compares complete nonce octet strings as specified by RFC
// 7296 section 2.8.2; leading zero octets remain significant.
func compareIKENonces(a, b []byte) int {
	return bytes.Compare(a, b)
}

// lowestNonceBelongsToFirst reports whether the lowest of the four nonces is
// from the first rekey exchange, whose candidate must therefore be deleted.
func lowestNonceBelongsToFirst(firstI, firstR, secondI, secondR []byte) bool {
	lowest := firstI
	first := true
	for _, candidate := range []struct {
		nonce []byte
		first bool
	}{{firstR, true}, {secondI, false}, {secondR, false}} {
		if bytes.Compare(candidate.nonce, lowest) < 0 {
			lowest, first = candidate.nonce, candidate.first
		}
	}
	return first
}

func supportedIKEGroup(group uint16) bool {
	for _, transform := range ikeProposal().Transforms {
		if transform.Type == TransDH && transform.ID == group {
			return true
		}
	}
	return false
}

func ikeGroupPreference(group uint16) int {
	preference := 0
	for _, transform := range ikeProposal().Transforms {
		if transform.Type != TransDH {
			continue
		}
		if transform.ID == group {
			return preference
		}
		preference++
	}
	return preference
}

// Keep the PRF across rekeys: strongSwan uses the old PRF for both SKEYSEED
// and expansion, while RFC 7296 §2.18 specifies the new PRF for expansion.
// Negotiating the same PRF interoperates without changing either derivation.
func ikeRekeyProposal(spi []byte, prfID uint16) Proposal {
	p := ikeProposal()
	p.SPI = spi
	transforms := p.Transforms[:0]
	for _, transform := range p.Transforms {
		if transform.Type != TransPRF || transform.ID == prfID {
			transforms = append(transforms, transform)
		}
	}
	p.Transforms = transforms
	return p
}

func selectIKERekeyProposal(proposal Proposal, keGroup, prfID uint16) ([]Transform, SASuite, uint16, bool) {
	// RFC 7296 §3.3.6 makes an entire proposal unacceptable when it contains
	// an unknown Transform Type. Unknown attributes are marked on individual
	// transforms by DecodeSA and skipped by exact matching below, allowing
	// another transform of the same type to be selected.
	var integ *Transform
	offeredInteg := false
	for i := range proposal.Transforms {
		transform := proposal.Transforms[i]
		switch transform.Type {
		case TransEncr, TransPRF, TransDH:
		case TransInteg:
			// An AEAD cipher needs no integrity transform, and a peer naming
			// NONE says the same thing as omitting it, the way
			// selectIKEProposal already takes it on the initial exchange.
			// Refusing it here would leave such a peer established and unable
			// to rekey from its own side. An integrity algorithm this end has
			// no key for is one unacceptable transform, not an unacceptable
			// proposal: "other transforms with the same Transform Type are
			// processed as usual".
			offeredInteg = true
			if integ == nil && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
				integ = &transform
			}
		default:
			return nil, SASuite{}, 0, false
		}
	}
	// The offer named integrity transforms and this end can take none of them,
	// so there is no complete set of parameters to select.
	if offeredInteg && integ == nil {
		return nil, SASuite{}, 0, false
	}
	offered := ikeRekeyProposal(nil, prfID).Transforms
	selected := make([]Transform, 0, 4)
	for _, typ := range []TransformType{TransEncr, TransPRF} {
		found := false
		for _, want := range offered {
			if want.Type != typ {
				continue
			}
			for _, got := range proposal.Transforms {
				if got == want {
					selected = append(selected, got)
					found = true
					break
				}
			}
			if found {
				break
			}
		}
		if !found {
			return nil, SASuite{}, 0, false
		}
	}
	matchingDH, preferredDH, ok := selectDHTransform(proposal.Transforms, keGroup, false)
	if !ok {
		return nil, SASuite{}, preferredDH, false
	}
	selected = append(selected, matchingDH)
	suite, err := suiteFromProposal(Proposal{Number: 1, Protocol: ProtoIKE, Transforms: selected})
	if err != nil {
		return nil, SASuite{}, 0, false
	}
	// "The accepted cryptographic suite MUST contain exactly one transform of
	// each type included in the proposal", RFC 7296 section 2.7, so an
	// integrity transform the peer offered is echoed rather than dropped. It
	// is appended after the suite is derived, which reads the three that
	// decide keys.
	if integ != nil {
		selected = append(selected, *integ)
	}
	return selected, suite, preferredDH, true
}
