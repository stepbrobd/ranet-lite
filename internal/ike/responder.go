package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

// Identity is one ASN1_DN name, the only identity type this profile uses.
// ranet asserts the name and checks it against the organization's single
// Ed25519 key, so the name selects which key verifies AUTH and nothing more.
type Identity struct {
	Organization string
	CommonName   string
	SerialNumber string
}

func (id Identity) String() string {
	return fmt.Sprintf("O=%s, CN=%s, serialNumber=%s", id.Organization, id.CommonName, id.SerialNumber)
}

// encodeID is the IDi or IDr payload body carrying this identity.
func (id Identity) encodeID() []byte {
	return EncodeID(ID_DER_ASN1_DN, EncodeIdentityDN(id.Organization, id.CommonName, id.SerialNumber))
}

// identityFromID parses an ID payload body into the name it asserts. The name
// only selects which key must verify AUTH; AUTH itself signs the bytes as
// received, so two encodings of one name are the same peer and neither can be
// accepted without that peer's key.
func identityFromID(body []byte) (Identity, error) {
	idType, data, err := DecodeID(body)
	if err != nil {
		return Identity{}, err
	}
	if idType != ID_DER_ASN1_DN {
		return Identity{}, fmt.Errorf("ike: identity type %d is not ASN1_DN", idType)
	}
	organization, commonName, serialNumber, err := DecodeIdentityDN(data)
	if err != nil {
		return Identity{}, err
	}
	return Identity{Organization: organization, CommonName: commonName, SerialNumber: serialNumber}, nil
}

// ResponderConfig is what answering an unsolicited peer needs, as against
// PeerConfig which describes one peer we dial. The asymmetry is the point: a
// responder does not know who is calling until IDi arrives, so the peer's key
// and the local endpoint identity are both resolved during the exchange.
type ResponderConfig struct {
	Hub *transport.Hub

	// Local holds every identity we answer to, one per configured endpoint
	// serial number. The initiator's IDr selects which one signs AUTH.
	Local           []Identity
	LocalPrivateKey ed25519.PrivateKey

	// Lookup resolves an initiator's asserted identity to the key that must
	// verify its AUTH. Returning false rejects the exchange. It is called
	// from several handshakes at once and must be safe for that.
	Lookup func(Identity) (ed25519.PublicKey, bool)

	// HandshakeTimeout bounds one exchange from the first datagram to an
	// established SA. Zero uses handshakeTimeout.
	HandshakeTimeout time.Duration

	ChildRekeyInterval time.Duration
	IKERekeyInterval   time.Duration
	RekeyMargin        time.Duration
	RekeyJitter        time.Duration
	RekeyRetryInitial  time.Duration
	RekeyRetryMax      time.Duration
}

const (
	// handshakeTimeout bounds the whole exchange. An initiator that opens an
	// SA and then goes quiet costs one mux and one SPI registration until it
	// expires, so this is the lifetime of the cheapest thing an unauthenticated
	// peer can make us allocate.
	handshakeTimeout = 30 * time.Second

	// cookieThreshold is the number of concurrent half-open SAs above which
	// IKE_SA_INIT is answered with a COOKIE instead of state (RFC 7296 section 2.6).
	// Below it, cookies cost a round trip for no benefit on a mesh whose peers
	// are all known.
	cookieThreshold = 32

	// halfOpenLimit caps what a flood can allocate even with a valid cookie.
	// A cookie proves return routability, not good behavior.
	halfOpenLimit = 256

	cookieLifetime = 2 * time.Minute
)

// Responder accepts IKE SAs that peers initiate to us on a shared hub. One
// Responder serves every peer; there is no per-peer state until IDi is
// authenticated, because until then there is no peer, only a datagram.
type Responder struct {
	cfg   ResponderConfig
	local map[Identity]struct{}

	mu            sync.Mutex
	halfOpen      int
	cookieSecret  [32]byte
	cookieVersion uint8
	cookieRotated time.Time
}

func NewResponder(cfg ResponderConfig) (*Responder, error) {
	if cfg.Hub == nil {
		return nil, fmt.Errorf("ike: responder needs a hub")
	}
	if len(cfg.LocalPrivateKey) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("ike: responder needs an Ed25519 private key")
	}
	if len(cfg.Local) == 0 {
		return nil, fmt.Errorf("ike: responder needs at least one local identity")
	}
	if cfg.Lookup == nil {
		return nil, fmt.Errorf("ike: responder needs a peer lookup")
	}
	r := &Responder{cfg: cfg, local: make(map[Identity]struct{}, len(cfg.Local))}
	for _, id := range cfg.Local {
		r.local[id] = struct{}{}
	}
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		return nil, err
	}
	r.cookieRotated = time.Now()
	return r, nil
}

// Serve reads unclaimed IKE datagrams and runs one handshake per initiator,
// calling onSession for each SA that reaches IKE_AUTH. Handshakes run
// concurrently: a peer that stalls halfway must not delay any other peer.
//
// It returns when ctx is cancelled or the hub's socket is gone, after every
// in-flight handshake has finished.
func (r *Responder) Serve(ctx context.Context, onSession func(*Session, Identity)) error {
	unclaimed := r.cfg.Hub.Listen()
	var running sync.WaitGroup
	defer running.Wait()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-r.cfg.Hub.Done():
			return fmt.Errorf("ike: responder hub closed")
		case datagram := <-unclaimed:
			running.Go(func() {
				session, id, err := r.handshake(ctx, datagram)
				if err != nil {
					slog.Debug("ike responder handshake failed", "peer", datagram.Endpoint, "err", err)
					return
				}
				onSession(session, id)
			})
		}
	}
}

// handshake runs IKE_SA_INIT and IKE_AUTH from the responder side for one
// initiator. Every failure before the mux exists is answered statelessly or
// silently; every failure after it closes the mux, so nothing survives a
// rejected exchange.
func (r *Responder) handshake(ctx context.Context, datagram transport.Unclaimed) (_ *Session, _ Identity, err error) {
	timeout := r.cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = handshakeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	request, err := DecodeMessage(datagram.Raw)
	if err != nil {
		return nil, Identity{}, fmt.Errorf("ike: decode IKE_SA_INIT request: %w", err)
	}
	header := request.Header
	if header.ExchangeType != IKE_SA_INIT || header.IsResponse() || !header.IsInitiator() ||
		header.MessageID != 0 || header.SPIResponder != 0 || header.SPIInitiator == 0 ||
		header.MajorVersion != 2 || header.Length != uint32(len(datagram.Raw)) {
		return nil, Identity{}, fmt.Errorf("ike: unclaimed datagram is not an IKE_SA_INIT request")
	}
	spiI := header.SPIInitiator

	saPayload, kePayload, noncePayload := request.find(PayloadSA), request.find(PayloadKE), request.find(PayloadNonce)
	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return nil, Identity{}, fmt.Errorf("ike: incomplete IKE_SA_INIT request")
	}
	ni := DecodeNonce(noncePayload.Body)
	if !validNonce(ni) {
		return nil, Identity{}, fmt.Errorf("ike: initiator nonce length %d is outside 16..256", len(ni))
	}
	// RFC 7296 section 2.5: a critical payload we do not implement has to be
	// refused by type rather than ignored, because the peer marked it as
	// changing what the message means.
	if unsupported, found := firstUnsupportedCritical(request.Payloads); found {
		r.sendStatelessNotify(datagram, spiI, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)})
		return nil, Identity{}, fmt.Errorf("ike: IKE_SA_INIT request marks payload type %d critical", unsupported)
	}

	// RFC 7296 section 2.6: under load, prove the initiator can receive at the
	// address it claims before allocating anything for it. The cookie is a
	// keyed hash of its nonce, address and SPI, so we still keep no state.
	if required, err := r.cookieRequired(request, ni, spiI, datagram.Endpoint); err != nil {
		return nil, Identity{}, err
	} else if required {
		return nil, Identity{}, fmt.Errorf("ike: cookie challenge sent")
	}

	// The cap comes before the Diffie-Hellman, not after it. Everything above
	// is answered from the datagram alone; everything below costs a key
	// exchange and a key derivation, measured at 72 microseconds and 5 KiB a
	// packet, which is a core saturated at fourteen thousand packets a second
	// by anyone who can reach this port. Counting the slot here is also what
	// gives cookieThreshold something real to read: a handshake still in its
	// key exchange is exactly the pressure the challenge of RFC 7296 section
	// 2.6 exists to answer.
	if !r.enterHalfOpen() {
		return nil, Identity{}, fmt.Errorf("ike: too many half-open SAs")
	}
	defer r.leaveHalfOpen()

	supportsIdentity, err := supportsSignatureHash(request.Payloads, HashIdentity)
	if err != nil {
		return nil, Identity{}, err
	}
	if !supportsIdentity {
		r.sendStatelessNotify(datagram, spiI, N_AUTHENTICATION_FAILED, nil)
		return nil, Identity{}, fmt.Errorf("ike: initiator did not advertise Ed25519 Identity hash support")
	}

	peerGroup, peerPublic, err := DecodeKE(kePayload.Body)
	if err != nil {
		return nil, Identity{}, fmt.Errorf("ike: decode KE: %w", err)
	}
	proposal, suite, err := selectIKEProposal(saPayload.Body, peerGroup)
	if err != nil {
		var wrongGroup *invalidKEError
		if errors.As(err, &wrongGroup) {
			group := make([]byte, 2)
			binary.BigEndian.PutUint16(group, wrongGroup.group)
			r.sendStatelessNotify(datagram, spiI, N_INVALID_KE_PAYLOAD, group)
			return nil, Identity{}, err
		}
		r.sendStatelessNotify(datagram, spiI, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Identity{}, err
	}

	dh, err := GenerateDH(suite.DHGroup)
	if err != nil {
		return nil, Identity{}, err
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return nil, Identity{}, err
	}
	nr := make([]byte, 32)
	if _, err := rand.Read(nr); err != nil {
		return nil, Identity{}, err
	}
	spiR := randUint64Nonzero()
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		return nil, Identity{}, err
	}

	// Per-SA state starts here; the half-open slot above is what bounds how
	// many of these can exist at once.
	mux, err := r.cfg.Hub.NewMuxTo(datagram.Endpoint)
	if err != nil {
		return nil, Identity{}, err
	}
	defer func() {
		if err != nil {
			_ = mux.Close()
		}
	}()
	stopCancel := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer stopCancel()
	// Register before the response goes out, so the initiator's IKE_AUTH
	// cannot race the receive loop back into the unclaimed queue.
	if err := mux.RegisterIKE(spiI); err != nil {
		return nil, Identity{}, err
	}
	defer func() {
		if err != nil {
			mux.UnregisterIKE(spiI)
		}
	}()

	response, err := r.buildSAInitResponse(spiI, spiR, proposal, suite, dh, nr)
	if err != nil {
		return nil, Identity{}, err
	}
	if err := mux.SendIKE(response); err != nil {
		return nil, Identity{}, err
	}

	session := &Session{
		childRetireDelay: 5 * time.Second,
		mux:              mux,
		current: &ikeContext{
			suite: suite,
			skD:   keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr,
			spiI: spiI, spiR: spiR, responder: true,
			// RFC 7296 section 2.2: the initiator consumed Message IDs 0 and 1, so
			// its next request is 2, while our own request counter starts at 0.
			nextPeerMID: 2, nextLocalMID: 0,
		},
		requests: make(chan *localRequest, 1),
	}

	id, err := session.completeResponderAuth(r, datagram.Raw, response, ni, nr, deadline)
	if err != nil {
		return nil, Identity{}, err
	}
	if err := session.SetRekeyTiming(r.cfg.RekeyMargin, r.cfg.RekeyJitter); err != nil {
		return nil, Identity{}, err
	}
	if err := session.SetRekeyIntervals(r.cfg.ChildRekeyInterval, r.cfg.IKERekeyInterval); err != nil {
		return nil, Identity{}, err
	}
	retryInitial, retryMax := r.cfg.RekeyRetryInitial, r.cfg.RekeyRetryMax
	if retryInitial == 0 && retryMax == 0 {
		retryInitial, retryMax = 5*time.Second, 5*time.Minute
	}
	if err := session.SetRekeyRetry(retryInitial, retryMax); err != nil {
		return nil, Identity{}, err
	}
	return session, id, nil
}

// buildSAInitResponse mirrors the initiator's IKE_SA_INIT, including the
// deliberately wrong NAT_DETECTION_SOURCE_IP. ranet-lite's transport accepts
// UDP-encapsulated ESP only, so the initiator has to conclude that we are
// behind a NAT; hashing a random address guarantees the mismatch that makes
// it, exactly as strongSwan's own force_encap does (ike_natd.c).
func (r *Responder) buildSAInitResponse(spiI, spiR uint64, proposal Proposal, suite SASuite, dh *DHKeyPair, nr []byte) ([]byte, error) {
	hashAlgos := make([]byte, 2)
	binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
	var fakeAddr [4]byte
	if _, err := rand.Read(fakeAddr[:]); err != nil {
		return nil, err
	}
	payloads := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadKE, Body: EncodeKE(suite.DHGroup, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		{Type: PayloadN, Body: EncodeNotify(Notify{
			Type: N_NAT_DETECTION_SOURCE_IP,
			Data: natDetectionHash(spiI, spiR, net.IP(fakeAddr[:]), 0),
		})},
	}
	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0}
	return (&Message{Header: header, Payloads: payloads}).Encode(), nil
}

// completeResponderAuth waits for IKE_AUTH, authenticates the initiator and
// answers with our own AUTH and the selected Child SA. A duplicate
// IKE_SA_INIT while waiting is answered with the identical response.
func (s *Session) completeResponderAuth(r *Responder, realMessage1, realMessage2, ni, nr []byte, deadline time.Time) (Identity, error) {
	ctx := s.current
	raw, source, err := s.awaitAuthRequest(realMessage1, realMessage2, deadline)
	if err != nil {
		return Identity{}, err
	}
	outer, err := DecodeMessage(raw)
	if err != nil {
		return Identity{}, fmt.Errorf("ike: decode IKE_AUTH request: %w", err)
	}
	innerFirst, plaintext, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
	if err != nil {
		return Identity{}, fmt.Errorf("ike: decrypt IKE_AUTH request: %w", err)
	}
	inner, err := decodeMessagePlaintext(innerFirst, plaintext)
	if err != nil {
		return Identity{}, fmt.Errorf("ike: malformed IKE_AUTH request: %w", err)
	}
	// Only an authenticated message may move where replies go (RFC 7296
	// section 2.23); decryption above is that proof.
	s.mux.AdoptEndpoint(source)

	if unsupported, found := firstUnsupportedCritical(inner); found {
		return Identity{}, s.rejectAuth(N_UNSUPPORTED_CRITICAL_PAYLOAD,
			fmt.Errorf("ike: IKE_AUTH request marks payload type %d critical", unsupported))
	}

	request := &Message{Header: outer.Header, Payloads: inner}
	idiPayload, authPayload := request.find(PayloadIDi), request.find(PayloadAUTH)
	if idiPayload == nil || authPayload == nil {
		return Identity{}, s.rejectAuth(N_AUTHENTICATION_FAILED, fmt.Errorf("ike: IKE_AUTH request has no IDi or AUTH"))
	}
	peerID, err := identityFromID(idiPayload.Body)
	if err != nil {
		return Identity{}, s.rejectAuth(N_AUTHENTICATION_FAILED, err)
	}
	peerKey, known := r.cfg.Lookup(peerID)
	if !known {
		return Identity{}, s.rejectAuth(N_AUTHENTICATION_FAILED, fmt.Errorf("ike: no registry entry for %s", peerID))
	}
	macedIDForI := prf(ctx.suite.PRFID, ctx.skpi, idiPayload.Body)
	if err := VerifyAuth(peerKey, concat(realMessage1, nr, macedIDForI), authPayload.Body); err != nil {
		return Identity{}, s.rejectAuth(N_AUTHENTICATION_FAILED, err)
	}

	// The initiator names us in IDr. Answering under a name it did not ask
	// for would let it verify a signature over the wrong identity, so an
	// unknown IDr is a rejection rather than a substitution.
	localID, err := r.localIdentity(request.find(PayloadIDr))
	if err != nil {
		return Identity{}, s.rejectAuth(N_AUTHENTICATION_FAILED, err)
	}
	idrBody := localID.encodeID()
	macedIDForR := prf(ctx.suite.PRFID, ctx.skpr, idrBody)
	authBody := BuildAuth(r.cfg.LocalPrivateKey, concat(realMessage2, ni, macedIDForR))

	// The IKE SA is authenticated from here (RFC 7296 section 2.21.2), so a Child
	// SA failure is reported inside an encrypted response rather than by
	// dropping the exchange.
	child, err := s.selectResponderChild(request, ni, nr)
	if err != nil {
		notify := N_NO_PROPOSAL_CHOSEN
		var wrongGroup *invalidKEError
		if errors.As(err, &wrongGroup) {
			notify = N_INVALID_KE_PAYLOAD
		}
		response, buildErr := s.response(ctx, 1, IKE_AUTH, []RawPayload{
			{Type: PayloadIDr, Body: idrBody},
			{Type: PayloadAUTH, Body: authBody},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: notify})},
		})
		if buildErr == nil {
			_ = s.mux.SendIKE(response)
		}
		return Identity{}, err
	}

	localSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(localSPI, child.sa.LocalSPI)
	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	response, err := s.response(ctx, 1, IKE_AUTH, []RawPayload{
		{Type: PayloadIDr, Body: idrBody},
		{Type: PayloadAUTH, Body: authBody},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{child.proposal(localSPI)})},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	})
	if err != nil {
		return Identity{}, err
	}
	if err := s.replaceChild(child.sa); err != nil {
		return Identity{}, err
	}
	// Retain the response before sending it: Session.Run answers a
	// retransmitted IKE_AUTH from here, and the initiator may retransmit
	// before we ever reach Run.
	s.stateMu.Lock()
	ctx.lastPeerResponseID, ctx.lastPeerResponse = 1, response
	s.stateMu.Unlock()
	if err := s.mux.SendIKE(response); err != nil {
		return Identity{}, err
	}
	return peerID, nil
}

// awaitAuthRequest waits for the initiator's IKE_AUTH, answering a repeat of
// the IKE_SA_INIT request with the identical response we already sent.
//
// The repeat has to match the retained request byte for byte. RFC 7296 section 2.1
// says the SPI and the source address are not enough to recognize a
// retransmission and that a responder matches on the whole packet, its hash or
// the nonce, and here that requirement is also what keeps this from being a
// reflector: a bare header naming a live SPIi, which anyone who opened one
// knows, would otherwise draw the full response at whatever source address it
// claimed.
func (s *Session) awaitAuthRequest(saInitRequest, saInitResponse []byte, deadline time.Time) ([]byte, transport.Endpoint, error) {
	ctx := s.current
	for {
		raw, source, err := s.mux.RecvIKEFromUntil(deadline)
		if err != nil {
			return nil, nil, fmt.Errorf("ike: waiting for IKE_AUTH: %w", err)
		}
		header, err := decodeHeader(raw)
		if err != nil || header.MajorVersion != 2 || header.Length != uint32(len(raw)) ||
			header.SPIInitiator != ctx.spiI || header.IsResponse() || !header.IsInitiator() {
			continue
		}
		if header.ExchangeType == IKE_SA_INIT && header.MessageID == 0 && header.SPIResponder == 0 {
			if !bytes.Equal(raw, saInitRequest) {
				continue
			}
			if err := s.mux.SendIKETo(saInitResponse, source); err != nil {
				return nil, nil, err
			}
			continue
		}
		if header.ExchangeType != IKE_AUTH || header.MessageID != 1 || header.SPIResponder != ctx.spiR {
			continue
		}
		return raw, source, nil
	}
}

// rejectAuth answers a failed authentication inside the SK payload, which the
// initiator can decrypt, and returns the underlying reason unchanged. The
// notify is deliberately uninformative: which of identity, key or signature
// failed is not the peer's business.
func (s *Session) rejectAuth(notify NotifyType, cause error) error {
	response, err := s.responseNotify(s.current, 1, IKE_AUTH, notify)
	if err == nil {
		_ = s.mux.SendIKE(response)
	}
	return cause
}

// responderChild is the Child SA selected from an IKE_AUTH request, kept
// together with the transform that has to be echoed in the response.
type responderChild struct {
	sa         ChildSA
	number     uint8
	encryption Transform
	dh         Transform
}

func (c responderChild) proposal(spi []byte) Proposal {
	encryption := c.encryption
	if encryption.ID == ENCR_CHACHA20_POLY1305 {
		// selectChildRequestProposal normalizes the key length so keymat has
		// one, but RFC 7296 section 3.3.5 forbids the Key Length attribute on a
		// fixed-key transform and section 3.3.6 requires the attributes of a selected
		// transform to come back unchanged. The offer carried none, so neither
		// may the answer. child_rekey.go does the same for CREATE_CHILD_SA.
		encryption.KeyLengthBits = 0
	}
	transforms := []Transform{encryption, {Type: TransESN, ID: ESN_NO}}
	if c.dh.Type != 0 {
		// A proposal that spelled out DH NONE gets it back: section 3.3.6 wants one
		// transform of every type the offer carried.
		transforms = append(transforms, c.dh)
	}
	return Proposal{
		// RFC 7296 section 3.3.1: "the proposal number in the SA payload MUST match
		// the number on the proposal sent that was accepted". A peer whose
		// second proposal we took has to see that number back.
		Number:     c.number,
		Protocol:   ProtoESP,
		SPI:        spi,
		Transforms: transforms,
	}
}

func (s *Session) selectResponderChild(request *Message, ni, nr []byte) (responderChild, error) {
	ctx := s.current
	saPayload := request.find(PayloadSA)
	tsi, tsr := request.find(PayloadTSi), request.find(PayloadTSr)
	if saPayload == nil || tsi == nil || tsr == nil {
		return responderChild{}, fmt.Errorf("ike: IKE_AUTH request has no Child SA")
	}
	if err := validateFullRangeSelectors(tsi, tsr); err != nil {
		return responderChild{}, err
	}
	// No KE payload accompanies the Child SA in IKE_AUTH: its keys come from
	// SK_d and the IKE_SA_INIT nonces (RFC 7296 section 2.17).
	selection, err := selectChildRequestProposal(saPayload.Body, nil, 0)
	if err != nil {
		return responderChild{}, err
	}
	if selection.dh.ID != 0 {
		return responderChild{}, fmt.Errorf("ike: Child SA in IKE_AUTH must not negotiate a DH group")
	}
	initiatorKey, responderKey, err := ChildSAKeymat(ctx.suite.PRFID, ctx.skD, ni, nr, selection.encryption.ID, selection.encryption.KeyLengthBits)
	if err != nil {
		return responderChild{}, err
	}
	return responderChild{
		sa: ChildSA{
			EncrID: selection.encryption.ID, EncrKeyBits: selection.encryption.KeyLengthBits,
			LocalSPI: randUint32Nonzero(), RemoteSPI: selection.remoteSPI,
			// The initiator encrypts with the initiator key, so that is what
			// arrives here, and our replies use the responder key.
			InboundKey: initiatorKey, OutboundKey: responderKey,
		},
		number:     selection.proposal.Number,
		encryption: selection.encryption,
		dh:         selection.dh,
	}, nil
}

// localIdentity resolves the IDr the initiator asked for, by name rather than
// by its bytes, and returns our own encoding of it. Our AUTH signs the IDr we
// send, and the initiator verifies against the IDr it receives, so answering
// in our own encoding is what the signature covers either way.
//
// A request without IDr is answered under our only identity; with more than
// one configured there is nothing to guess from, so it is rejected.
func (r *Responder) localIdentity(idr *RawPayload) (Identity, error) {
	if idr == nil {
		if len(r.cfg.Local) != 1 {
			return Identity{}, fmt.Errorf("ike: IKE_AUTH request omits IDr and %d local identities are configured", len(r.cfg.Local))
		}
		return r.cfg.Local[0], nil
	}
	id, err := identityFromID(idr.Body)
	if err != nil {
		return Identity{}, err
	}
	if _, ok := r.local[id]; !ok {
		return Identity{}, fmt.Errorf("ike: IKE_AUTH request names %s, which we do not answer to", id)
	}
	return id, nil
}

// firstUnsupportedCritical reports the first payload this profile does not
// implement whose critical bit is set. An unrecognized payload without the bit
// is skipped, which is what the flag is for.
func firstUnsupportedCritical(payloads []RawPayload) (PayloadType, bool) {
	for _, payload := range payloads {
		if payload.Critical && !supportedPayloadType(payload.Type) {
			return payload.Type, true
		}
	}
	return 0, false
}

func (r *Responder) enterHalfOpen() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.halfOpen >= halfOpenLimit {
		return false
	}
	r.halfOpen++
	return true
}

func (r *Responder) leaveHalfOpen() {
	r.mu.Lock()
	r.halfOpen--
	r.mu.Unlock()
}

// cookieRequired implements RFC 7296 section 2.6. Below the threshold it does
// nothing. Above it, a request without a currently valid cookie is answered
// with one and reports true so the caller stops without allocating; the
// initiator retries with the cookie echoed as its first payload.
func (r *Responder) cookieRequired(request *Message, ni []byte, spiI uint64, endpoint transport.Endpoint) (bool, error) {
	r.mu.Lock()
	pressure := r.halfOpen >= cookieThreshold
	if pressure && time.Since(r.cookieRotated) > cookieLifetime {
		if _, err := rand.Read(r.cookieSecret[:]); err != nil {
			r.mu.Unlock()
			return false, err
		}
		r.cookieVersion++
		r.cookieRotated = time.Now()
	}
	secret, version := r.cookieSecret, r.cookieVersion
	r.mu.Unlock()
	if !pressure {
		return false, nil
	}
	expected := cookieValue(secret, version, ni, spiI, endpoint)
	for _, payload := range request.Payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err == nil && notify.Type == N_COOKIE && hmac.Equal(notify.Data, expected) {
			return false, nil
		}
	}
	header := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0}
	message := &Message{Header: header, Payloads: []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: expected})},
	}}
	_ = r.cfg.Hub.SendIKETo(message.Encode(), endpoint)
	return true, nil
}

// cookieValue is the version octet followed by a keyed hash over everything
// that identifies this attempt, so the cookie is bound to the nonce, the SPI
// and the address it was sent to and cannot be replayed for another.
func cookieValue(secret [32]byte, version uint8, ni []byte, spiI uint64, endpoint transport.Endpoint) []byte {
	mac := hmac.New(sha256.New, secret[:])
	mac.Write(ni)
	var spi [8]byte
	binary.BigEndian.PutUint64(spi[:], spiI)
	mac.Write(spi[:])
	if addr, ok := endpoint.(fmt.Stringer); ok {
		mac.Write([]byte(addr.String()))
	}
	return append([]byte{version}, mac.Sum(nil)...)
}

// sendStatelessNotify answers an IKE_SA_INIT we will not carry forward. The
// responder SPI is zero because no SA was created (RFC 7296 section 2.6.1).
func (r *Responder) sendStatelessNotify(datagram transport.Unclaimed, spiI uint64, notify NotifyType, data []byte) {
	header := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0}
	message := &Message{Header: header, Payloads: []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: notify, Data: data})},
	}}
	_ = r.cfg.Hub.SendIKETo(message.Encode(), datagram.Endpoint)
}

// selectIKEProposal picks one transform of each type from the initiator's
// offer, preferring our own order so the strongest mutually supported
// algorithm wins rather than whichever the peer listed first. A proposal that
// is acceptable except for its DH group reports the group we want, which the
// caller turns into INVALID_KE_PAYLOAD.
//
// An unknown transform type rejects the whole proposal rather than being
// skipped. RFC 7296 section 3.3.6 allows skipping unsupported alternatives of
// a known type, but a type we cannot name may change what the proposal means,
// and the child selection in this package already takes the same view.
func selectIKEProposal(body []byte, keGroup uint16) (Proposal, SASuite, error) {
	proposals, err := DecodeSA(body)
	if err != nil {
		return Proposal{}, SASuite{}, fmt.Errorf("ike: invalid IKE SA proposal: %w", err)
	}
	offered := ikeProposal().Transforms
	var preferredGroup uint16
	for _, proposal := range proposals {
		if proposal.Number == 0 || proposal.Protocol != ProtoIKE || len(proposal.SPI) != 0 {
			continue
		}
		known := true
		for _, transform := range proposal.Transforms {
			switch transform.Type {
			case TransEncr, TransPRF, TransDH:
			default:
				known = false
			}
		}
		if !known {
			continue
		}
		// An offered transform carries no unsupported attributes, so struct
		// equality already rejects one whose attributes we could not parse.
		pick := func(want TransformType) (Transform, bool) {
			for _, candidate := range offered {
				if candidate.Type != want {
					continue
				}
				for _, transform := range proposal.Transforms {
					if transform == candidate {
						return candidate, true
					}
				}
			}
			return Transform{}, false
		}
		encr, haveEncr := pick(TransEncr)
		prfT, havePRF := pick(TransPRF)
		dhT, haveDH := pick(TransDH)
		if !haveEncr || !havePRF || !haveDH {
			continue
		}
		if dhT.ID != keGroup {
			// The offer is acceptable but the initiator guessed the wrong
			// group for its KE payload. Remember the first such group and
			// keep looking for a proposal that needs no extra round trip.
			if preferredGroup == 0 {
				preferredGroup = dhT.ID
			}
			continue
		}
		keyBits := encr.KeyLengthBits
		if encr.ID == ENCR_CHACHA20_POLY1305 {
			keyBits = 256
		}
		selected := Proposal{Number: proposal.Number, Protocol: ProtoIKE, Transforms: []Transform{encr, prfT, dhT}}
		return selected, SASuite{EncrID: encr.ID, EncrKeyBits: keyBits, PRFID: prfT.ID, DHGroup: dhT.ID}, nil
	}
	if preferredGroup != 0 {
		return Proposal{}, SASuite{}, &invalidKEError{preferredGroup}
	}
	return Proposal{}, SASuite{}, fmt.Errorf("ike: no acceptable IKE SA proposal")
}
