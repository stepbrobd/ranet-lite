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
	"net/netip"
	"sync"
	"sync/atomic"
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
// PeerConfig which describes one peer we dial. A responder does not know who
// is calling until IDi arrives, so the peer's key and the local endpoint
// identity are both resolved during the exchange rather than configured.
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

	// cookieThreshold is the number of concurrent half-open SAs at which
	// IKE_SA_INIT starts being answered with a COOKIE instead of state (RFC
	// 7296 section 2.6). It is not the only thing that demands one: see
	// halfOpenPerSourceWithoutCookie, which reaches the same answer for one
	// address on an idle node. Below both, cookies cost a round trip for no
	// benefit on a mesh whose peers are all known.
	cookieThreshold = 32

	// halfOpenLimit caps what a flood can allocate even with a valid cookie.
	// A cookie proves return routability, not good behavior.
	halfOpenLimit = 256

	// halfOpenPerSource is what one address can hold of that. Without it the
	// cap is first come from a single address: an initiator that sends
	// IKE_SA_INIT and never IKE_AUTH holds a slot for the whole
	// handshakeTimeout, so eight and a half packets a second park every slot
	// forever, and from then on every legitimate peer answers its cookie
	// correctly and is refused anyway. That partition costs one real address
	// and about seventeen packets a second.
	//
	// The unit is the address alone. Keyed by the whole endpoint it bounds a
	// UDP flow instead, and sixteen source ports from one address take all 256
	// slots again, which was measured end to end before this was fixed. Both
	// backends unmap, so a v4-mapped source and a plain v4 source are one key,
	// and linux's zone for a link-local source drops out with the port.
	//
	// A refusal is silent because RFC 7296 section 2.21.1 does not give
	// IKE_SA_INIT a notify for it, and inventing one is worse than the retry.
	// The bound is well above what one peer produces: it opens one exchange
	// per endpoint pair and a retransmission that arrives before the response
	// is registered starts another, so the ceiling is the retransmission
	// budget rather than the number of SAs. A NAT with more than sixteen mesh
	// nodes behind one address restarting at once is the case it costs.
	halfOpenPerSource = 16

	// halfOpenPerSourceWithoutCookie is how many of one address's share it may
	// take before it has to prove return routability, whatever the global
	// pressure is. One is too few: a peer with two local endpoints dials the
	// same address twice, and a retransmission that arrives before the
	// response is registered starts another exchange, so a small number keeps
	// the ordinary cases free of a round trip while a spoofer can burn only
	// that many of a victim's slots.
	halfOpenPerSourceWithoutCookie = 2

	cookieLifetime = 2 * time.Minute
)

// Accepted names both ends of an SA a peer opened to us. The local identity
// is the endpoint the initiator addressed in IDr, so the pair identifies one
// path through the mesh the same way a dialed session does, rather than just
// naming the peer.
type Accepted struct {
	Peer  Identity
	Local Identity
}

// Responder accepts IKE SAs that peers initiate to us on a shared hub. One
// Responder serves every peer; there is no per-peer state until IDi is
// authenticated, because until then there is no peer, only a datagram.
type Responder struct {
	cfg   ResponderConfig
	local map[Identity]struct{}

	// started and failureReported bound how often a failed inbound handshake
	// is said out loud, on the monotonic clock, primed one interval in the
	// past so the first one is not swallowed. See noteHandshakeFailure.
	started         time.Time
	failureReported atomic.Int64

	mu       sync.Mutex
	halfOpen int
	// halfOpenBySource is how many of those one address is holding.
	halfOpenBySource map[netip.Addr]int
	cookieSecret     [32]byte
	// previousSecret is the secret one rotation back, and previousValid says
	// whether there has been a rotation at all. A cookie is issued and echoed
	// a round trip apart, so rotating without keeping the old one refuses
	// every cookie in flight at that moment; the initiator accepts one COOKIE
	// per dial, so it then retransmits a cookie that can never be accepted
	// until its whole budget runs out. One generation back is all it takes,
	// because a cookie older than that is older than cookieLifetime.
	previousSecret [32]byte
	previousValid  bool
	cookieVersion  uint8
	cookieRotated  time.Time
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
	r := &Responder{cfg: cfg, local: make(map[Identity]struct{}, len(cfg.Local)), started: time.Now()}
	r.failureReported.Store(-int64(handshakeFailureInterval))
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
// It returns when ctx is canceled or the hub's socket is gone, after every
// in-flight handshake has finished.
func (r *Responder) Serve(ctx context.Context, onSession func(*Session, Accepted)) error {
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
				session, accepted, err := r.handshake(ctx, datagram)
				if err != nil {
					// Warn rather than debug: this is the whole responder side
					// of "that peer cannot connect", and at the default level
					// it said nothing at all. Anyone who can reach the port
					// can drive it, so it is rate limited rather than free.
					r.noteHandshakeFailure(datagram.Endpoint, err)
					return
				}
				onSession(session, accepted)
			})
		}
	}
}

// handshake runs IKE_SA_INIT and IKE_AUTH from the responder side for one
// initiator. Every failure before the mux exists is answered statelessly or
// silently; every failure after it closes the mux, so nothing survives a
// rejected exchange.
func (r *Responder) handshake(ctx context.Context, datagram transport.Unclaimed) (_ *Session, _ Accepted, err error) {
	timeout := r.cfg.HandshakeTimeout
	if timeout <= 0 {
		timeout = handshakeTimeout
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	deadline, _ := ctx.Deadline()

	request, err := DecodeMessage(datagram.Raw)
	if err != nil {
		return nil, Accepted{}, fmt.Errorf("ike: decode IKE_SA_INIT request: %w", err)
	}
	header := request.Header
	if header.ExchangeType != IKE_SA_INIT || header.IsResponse() || !header.IsInitiator() ||
		header.MessageID != 0 || header.SPIResponder != 0 || header.SPIInitiator == 0 ||
		header.MajorVersion != 2 || header.Length != uint32(len(datagram.Raw)) {
		return nil, Accepted{}, fmt.Errorf("ike: unclaimed datagram is not an IKE_SA_INIT request")
	}
	spiI := header.SPIInitiator

	saPayload, kePayload, noncePayload := request.find(PayloadSA), request.find(PayloadKE), request.find(PayloadNonce)
	if saPayload == nil || kePayload == nil || noncePayload == nil {
		return nil, Accepted{}, fmt.Errorf("ike: incomplete IKE_SA_INIT request")
	}
	ni := DecodeNonce(noncePayload.Body)
	if !validNonce(ni) {
		return nil, Accepted{}, fmt.Errorf("ike: initiator nonce length %d is outside 16..256", len(ni))
	}
	// RFC 7296 section 2.5: a critical payload we do not implement has to be
	// refused by type rather than ignored, because the peer marked it as
	// changing what the message means.
	if unsupported, found := firstUnsupportedCritical(request.Payloads); found {
		r.sendStatelessNotify(datagram, spiI, N_UNSUPPORTED_CRITICAL_PAYLOAD, []byte{byte(unsupported)})
		return nil, Accepted{}, fmt.Errorf("ike: IKE_SA_INIT request marks payload type %d critical", unsupported)
	}

	// RFC 7296 section 2.6: under load, prove the initiator can receive at the
	// address it claims before allocating anything for it. The cookie is a
	// keyed hash of its nonce, address and SPI, so we still keep no state.
	if required, err := r.cookieRequired(request, ni, spiI, datagram.Endpoint); err != nil {
		return nil, Accepted{}, err
	} else if required {
		return nil, Accepted{}, fmt.Errorf("ike: cookie challenge sent")
	}

	// The cap comes before the Diffie-Hellman, not after it. Everything above
	// is answered from the datagram alone; everything below costs a key
	// exchange and a key derivation, measured at 72 microseconds and 5 KiB a
	// packet, which is a core saturated at fourteen thousand packets a second
	// by anyone who can reach this port. Counting the slot here is also what
	// gives cookieThreshold something real to read: a handshake still in its
	// key exchange is exactly the pressure the challenge of RFC 7296 section
	// 2.6 exists to answer.
	source := datagram.Endpoint.AddrPort().Addr()
	if !r.enterHalfOpen(source) {
		return nil, Accepted{}, fmt.Errorf("ike: too many half-open SAs")
	}
	defer r.leaveHalfOpen(source)

	supportsIdentity, err := supportsSignatureHash(request.Payloads, HashIdentity)
	if err != nil {
		return nil, Accepted{}, err
	}
	if !supportsIdentity {
		// NO_PROPOSAL_CHOSEN rather than AUTHENTICATION_FAILED: RFC 7296
		// section 3.10.1 defines the latter as "sent in the response to an
		// IKE_AUTH message", and an authentication method this responder
		// cannot use is exactly what the former is for, "any case where the
		// offered proposals (including but not limited to SA payload values,
		// USE_TRANSPORT_MODE notify, IPCOMP_SUPPORTED notify) are not
		// acceptable for the responder". Section
		// 2.21.1 makes either end the exchange, so the peer behaves the same
		// way and the registry is the tiebreak.
		r.sendStatelessNotify(datagram, spiI, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Accepted{}, fmt.Errorf("ike: initiator did not advertise Ed25519 Identity hash support")
	}

	peerGroup, peerPublic, err := DecodeKE(kePayload.Body)
	if err != nil {
		return nil, Accepted{}, fmt.Errorf("ike: decode KE: %w", err)
	}
	proposal, suite, err := selectIKEProposal(saPayload.Body, peerGroup)
	if err != nil {
		var wrongGroup *invalidKEError
		if errors.As(err, &wrongGroup) {
			group := make([]byte, 2)
			binary.BigEndian.PutUint16(group, wrongGroup.group)
			r.sendStatelessNotify(datagram, spiI, N_INVALID_KE_PAYLOAD, group)
			return nil, Accepted{}, err
		}
		r.sendStatelessNotify(datagram, spiI, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Accepted{}, err
	}

	// The rest of RFC 7296 section 2.10 needs the PRF, which the proposal has
	// just settled: a nonce "MUST be at least half the key size of the
	// negotiated pseudorandom function". This is the one surface an
	// unauthenticated peer reaches first, so leaving it on the length check
	// alone left it as the one place a short nonce was taken.
	if !validNonceFor(ni, suite.PRFID) {
		r.sendStatelessNotify(datagram, spiI, N_NO_PROPOSAL_CHOSEN, nil)
		return nil, Accepted{}, fmt.Errorf("ike: initiator nonce length %d is short for the negotiated PRF", len(ni))
	}

	dh, err := GenerateDH(suite.DHGroup)
	if err != nil {
		return nil, Accepted{}, err
	}
	shared, err := dh.SharedSecret(peerPublic)
	if err != nil {
		return nil, Accepted{}, err
	}
	nr := make([]byte, 32)
	if _, err := rand.Read(nr); err != nil {
		return nil, Accepted{}, err
	}
	spiR := randUint64Nonzero()
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		return nil, Accepted{}, err
	}

	// Per-SA state starts here; the half-open slot above is what bounds how
	// many of these can exist at once.
	mux, err := r.cfg.Hub.NewMuxTo(datagram.Endpoint)
	if err != nil {
		return nil, Accepted{}, err
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
		return nil, Accepted{}, err
	}
	defer func() {
		if err != nil {
			mux.UnregisterIKE(spiI)
		}
	}()

	response, err := r.buildSAInitResponse(spiI, spiR, proposal, suite, dh, nr, datagram.Endpoint)
	if err != nil {
		return nil, Accepted{}, err
	}
	if err := mux.SendIKE(response); err != nil {
		return nil, Accepted{}, err
	}

	session := &Session{
		started:          time.Now(),
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

	accepted, err := session.completeResponderAuth(r, datagram.Raw, response, ni, nr, deadline)
	if err != nil {
		return nil, Accepted{}, err
	}
	if err := session.SetRekeyTiming(r.cfg.RekeyMargin, r.cfg.RekeyJitter); err != nil {
		return nil, Accepted{}, err
	}
	if err := session.SetRekeyIntervals(r.cfg.ChildRekeyInterval, r.cfg.IKERekeyInterval); err != nil {
		return nil, Accepted{}, err
	}
	retryInitial, retryMax := r.cfg.RekeyRetryInitial, r.cfg.RekeyRetryMax
	if retryInitial == 0 && retryMax == 0 {
		retryInitial, retryMax = 5*time.Second, 5*time.Minute
	}
	if err := session.SetRekeyRetry(retryInitial, retryMax); err != nil {
		return nil, Accepted{}, err
	}
	session.noteEstablished()
	return session, accepted, nil
}

// buildSAInitResponse mirrors the initiator's IKE_SA_INIT, including the
// deliberately wrong NAT_DETECTION_SOURCE_IP. ranet-lite's transport accepts
// UDP-encapsulated ESP only, so the initiator has to conclude that we are
// behind a NAT; hashing a random address guarantees the mismatch that makes
// it, exactly as strongSwan's own force_encap does (ike_natd.c).
//
// Both notifies have to be present. strongSwan enables NAT traversal only
// when it has seen a source and a destination notify, and treats one alone as
// a peer that does not implement RFC 7296 section 2.23 at all, so sending the
// mismatching source on its own leaves it building raw ESP that no userspace
// transport ever sees. The destination hash is the honest one, over the
// address this datagram actually came from.
//
// It follows that the peer must be reachable on the port it already knows.
// RFC 7296 section 2.23 obliges a conformant initiator that sees the mismatch
// to move everything to UDP 4500, and nothing here binds 4500 separately, so
// the registry port has to be the port both ends keep using. strongSwan does
// that when charon.port_nat_t is set to it, which the fleet and the
// integration test both configure, and a peer left on the default would float
// away to a socket that is not listening. Config rejects port 500 outright for
// the related reason that the non-ESP marker cannot be used there.
func (r *Responder) buildSAInitResponse(spiI, spiR uint64, proposal Proposal, suite SASuite, dh *DHKeyPair, nr []byte, endpoint transport.Endpoint) ([]byte, error) {
	hashAlgos := make([]byte, 2)
	binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
	var fakeAddr [4]byte
	if _, err := rand.Read(fakeAddr[:]); err != nil {
		return nil, err
	}
	peer := endpoint.AddrPort()
	payloads := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadKE, Body: EncodeKE(suite.DHGroup, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(nr)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		{Type: PayloadN, Body: EncodeNotify(Notify{
			Type: N_NAT_DETECTION_SOURCE_IP,
			Data: natDetectionHash(spiI, spiR, net.IP(fakeAddr[:]), 0),
		})},
		{Type: PayloadN, Body: EncodeNotify(Notify{
			Type: N_NAT_DETECTION_DESTINATION_IP,
			Data: natDetectionHash(spiI, spiR, net.IP(peer.Addr().AsSlice()), peer.Port()),
		})},
	}
	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0}
	return (&Message{Header: header, Payloads: payloads}).Encode(), nil
}

// completeResponderAuth waits for IKE_AUTH, authenticates the initiator and
// answers with our own AUTH and the selected Child SA. A duplicate
// IKE_SA_INIT while waiting is answered with the identical response.
func (s *Session) completeResponderAuth(r *Responder, realMessage1, realMessage2, ni, nr []byte, deadline time.Time) (Accepted, error) {
	ctx := s.current
	got, err := s.awaitAuthRequest(realMessage1, realMessage2, deadline)
	if err != nil {
		return Accepted{}, err
	}
	outer, source := got.outer, got.source
	inner, err := decodeMessagePlaintext(got.innerFirst, got.plaintext)
	if err != nil {
		return Accepted{}, fmt.Errorf("ike: malformed IKE_AUTH request: %w", err)
	}
	// Only an authenticated message may move where replies go (RFC 7296
	// section 2.23); decryption above is that proof.
	s.mux.AdoptEndpoint(source)

	if unsupported, found := firstUnsupportedCritical(inner); found {
		return Accepted{}, s.rejectAuth(N_UNSUPPORTED_CRITICAL_PAYLOAD,
			fmt.Errorf("ike: IKE_AUTH request marks payload type %d critical", unsupported))
	}

	request := &Message{Header: outer.Header, Payloads: inner}
	idiPayload, authPayload := request.find(PayloadIDi), request.find(PayloadAUTH)
	if idiPayload == nil || authPayload == nil {
		return Accepted{}, s.rejectAuth(N_AUTHENTICATION_FAILED, fmt.Errorf("ike: IKE_AUTH request has no IDi or AUTH"))
	}
	peerID, err := identityFromID(idiPayload.Body)
	if err != nil {
		return Accepted{}, s.rejectAuth(N_AUTHENTICATION_FAILED, err)
	}
	peerKey, known := r.cfg.Lookup(peerID)
	if !known {
		return Accepted{}, s.rejectAuth(N_AUTHENTICATION_FAILED, fmt.Errorf("ike: no registry entry for %s", peerID))
	}
	macedIDForI := prf(ctx.suite.PRFID, ctx.skpi, idiPayload.Body)
	if err := VerifyAuth(peerKey, concat(realMessage1, nr, macedIDForI), authPayload.Body); err != nil {
		return Accepted{}, s.rejectAuth(N_AUTHENTICATION_FAILED, err)
	}

	// The initiator names us in IDr. Answering under a name it did not ask
	// for would let it verify a signature over the wrong identity, so an
	// unknown IDr is a rejection rather than a substitution.
	localID, err := r.localIdentity(request.find(PayloadIDr))
	if err != nil {
		return Accepted{}, s.rejectAuth(N_AUTHENTICATION_FAILED, err)
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
		return Accepted{}, err
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
		return Accepted{}, err
	}
	if err := s.replaceChild(child.sa); err != nil {
		return Accepted{}, err
	}
	// Retain the response before sending it: Session.Run answers a
	// retransmitted IKE_AUTH from here, and the initiator may retransmit
	// before we ever reach Run.
	s.stateMu.Lock()
	ctx.lastPeerResponseID, ctx.lastPeerResponse = 1, response
	s.stateMu.Unlock()
	if err := s.mux.SendIKE(response); err != nil {
		return Accepted{}, err
	}
	return Accepted{Peer: peerID, Local: localID}, nil
}

// authRequest is the first IKE_AUTH request that decrypted under this
// half-open SA's keys, with the pieces that proved it.
type authRequest struct {
	raw        []byte
	outer      *Message
	innerFirst PayloadType
	plaintext  []byte
	source     transport.Endpoint
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
func (s *Session) awaitAuthRequest(saInitRequest, saInitResponse []byte, deadline time.Time) (*authRequest, error) {
	ctx := s.current
	for {
		raw, source, err := s.mux.RecvIKEFromUntil(deadline)
		if err != nil {
			return nil, fmt.Errorf("ike: waiting for IKE_AUTH: %w", err)
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
				return nil, err
			}
			continue
		}
		if header.ExchangeType != IKE_AUTH || header.MessageID != 1 || header.SPIResponder != ctx.spiR {
			continue
		}
		// Decoded and decrypted here rather than by the caller, so that a
		// datagram carrying the right header and the wrong contents is one
		// more thing to keep waiting past. Anyone who can see the responder
		// SPI can send one, and acting on it would end a handshake this end
		// has already paid for. It is the rule sendRecv follows for the rest
		// of the session, RFC 7296 section 2.21 and RFC 7815 section 2.1:
		// nothing unauthenticated changes state. The deadline is what ends
		// the wait.
		outer, err := DecodeMessage(raw)
		if err != nil {
			continue
		}
		innerFirst, plaintext, err := decryptMessagePlaintext(ctx.suite, ctx.peerEncryptionKey(), raw, outer)
		if err != nil {
			continue
		}
		return &authRequest{raw: raw, outer: outer, innerFirst: innerFirst, plaintext: plaintext, source: source}, nil
	}
}

// handshakeFailureInterval bounds how often a failed inbound handshake is
// logged. Anyone who can reach the port can cause one, so the line has to be
// rare; but at debug it was invisible at the default level, and an operator
// looking at "that peer cannot connect" had nothing on this side to read.
const handshakeFailureInterval = 10 * time.Second

func (r *Responder) noteHandshakeFailure(endpoint transport.Endpoint, err error) {
	now := int64(time.Since(r.started))
	previous := r.failureReported.Load()
	if now-previous < int64(handshakeFailureInterval) || !r.failureReported.CompareAndSwap(previous, now) {
		slog.Debug("ike responder handshake failed", "peer", endpoint, "err", err)
		return
	}
	slog.Warn("ike responder handshake failed", "peer", endpoint, "err", err)
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
	integ      Transform
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
	// A proposal that spelled out DH NONE or INTEG NONE gets it back: section
	// 2.7 wants one transform of every type the offer carried.
	if c.dh.Type != 0 {
		transforms = append(transforms, c.dh)
	}
	if c.integ.Type != 0 {
		transforms = append(transforms, c.integ)
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
		integ:      selection.integ,
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
// is skipped, which the flag exists for.
func firstUnsupportedCritical(payloads []RawPayload) (PayloadType, bool) {
	for _, payload := range payloads {
		if payload.Critical && !supportedPayloadType(payload.Type) {
			return payload.Type, true
		}
	}
	return 0, false
}

func (r *Responder) enterHalfOpen(source netip.Addr) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.halfOpen >= halfOpenLimit || r.halfOpenBySource[source] >= halfOpenPerSource {
		return false
	}
	if r.halfOpenBySource == nil {
		r.halfOpenBySource = make(map[netip.Addr]int)
	}
	r.halfOpen++
	r.halfOpenBySource[source]++
	return true
}

func (r *Responder) leaveHalfOpen(source netip.Addr) {
	r.mu.Lock()
	// Floored, because a count that went negative would disable the cookie
	// threshold and the cap together and nothing would ever bring it back.
	if r.halfOpen > 0 {
		r.halfOpen--
	}
	if r.halfOpenBySource[source] <= 1 {
		delete(r.halfOpenBySource, source)
	} else {
		r.halfOpenBySource[source]--
	}
	r.mu.Unlock()
}

// cookieRequired implements RFC 7296 section 2.6. With neither the global
// count nor this address's share of it under pressure it does nothing. Under
// either, a request without a currently valid cookie is answered with one and
// reports true so the caller stops without allocating; the initiator retries
// with the cookie echoed as its first payload.
func (r *Responder) cookieRequired(request *Message, ni []byte, spiI uint64, endpoint transport.Endpoint) (bool, error) {
	source := endpoint.AddrPort().Addr()
	r.mu.Lock()
	// Under pressure globally, or past what one address may hold without
	// having proved it can receive. The second is what stops a spoofer
	// spending a named peer's whole share while the node is idle: with the
	// global threshold alone, floor(cookieThreshold/halfOpenPerSource)
	// addresses can be locked out by an off-path source, for sixteen packets
	// every thirty seconds each, and the victim is then refused in silence.
	pressure := r.halfOpen >= cookieThreshold ||
		r.halfOpenBySource[source] >= halfOpenPerSourceWithoutCookie
	if pressure && time.Since(r.cookieRotated) > cookieLifetime {
		var next [32]byte
		if _, err := rand.Read(next[:]); err != nil {
			r.mu.Unlock()
			return false, err
		}
		r.previousSecret, r.previousValid = r.cookieSecret, true
		r.cookieSecret = next
		r.cookieVersion++
		r.cookieRotated = time.Now()
	}
	secret, version := r.cookieSecret, r.cookieVersion
	previous, havePrevious := r.previousSecret, r.previousValid
	r.mu.Unlock()
	if !pressure {
		return false, nil
	}
	expected := cookieValue(secret, version, ni, spiI, endpoint)
	accepted := [][]byte{expected}
	if havePrevious {
		accepted = append(accepted, cookieValue(previous, version-1, ni, spiI, endpoint))
	}
	for _, payload := range request.Payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil || notify.Type != N_COOKIE {
			continue
		}
		for _, candidate := range accepted {
			if hmac.Equal(notify.Data, candidate) {
				return false, nil
			}
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
	mac.Write([]byte(endpoint.String()))
	return append([]byte{version}, mac.Sum(nil)...)
}

// sendStatelessNotify answers an IKE_SA_INIT we will not carry forward. The
// responder SPI is zero because no SA was created (RFC 7296 section 2.6).
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
// RFC 7296 section 3.3.6 splits the two refusals: a Transform Type this end
// cannot name makes the whole proposal unacceptable, because a type we cannot
// name may change what the proposal means, while an unacceptable transform of
// a known type makes only that transform unacceptable and "other transforms
// with the same Transform Type are processed as usual". Either way the other
// proposals in the same SA payload are still considered, and the child
// selection in this package takes the same view.
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
		var integ *Transform
		offeredInteg := false
		for i := range proposal.Transforms {
			transform := proposal.Transforms[i]
			switch transform.Type {
			case TransEncr, TransPRF, TransDH:
			case TransInteg:
				// RFC 7296 section 3.3.2's transform registry gives integrity
				// algorithm 0 the name NONE, and an AEAD cipher needs no
				// integrity transform, so a peer spelling out NONE says the
				// same thing as omitting it. Anything else is a transform this
				// implementation has no key for, because every cipher it
				// offers is combined mode, and section 3.3.6 makes that one
				// transform unacceptable rather than the proposal it sits in.
				// A peer offering an integrity algorithm alongside NONE, which
				// is the shape an implementation that also has non-AEAD
				// ciphers produces, therefore still gets an answer.
				offeredInteg = true
				if integ == nil && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
					integ = &transform
				}
			default:
				known = false
			}
		}
		if !known {
			continue
		}
		// Every alternative of a type the offer did include was unacceptable,
		// so there is no complete set of parameters to take out of this
		// proposal. The rest of the SA payload is still considered.
		if offeredInteg && integ == nil {
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
		// "The accepted cryptographic suite MUST contain exactly one transform
		// of each type included in the proposal", RFC 7296 section 2.7, so an
		// integrity transform the initiator offered is echoed back rather than
		// dropped from the answer.
		transforms := []Transform{encr, prfT, dhT}
		if integ != nil {
			transforms = append(transforms, *integ)
		}
		selected := Proposal{Number: proposal.Number, Protocol: ProtoIKE, Transforms: transforms}
		return selected, SASuite{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, PRFID: prfT.ID, DHGroup: dhT.ID}, nil
	}
	if preferredGroup != 0 {
		return Proposal{}, SASuite{}, &invalidKEError{preferredGroup}
	}
	return Proposal{}, SASuite{}, fmt.Errorf("ike: no acceptable IKE SA proposal")
}
