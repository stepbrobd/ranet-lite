package ike

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// PeerConfig describes everything needed to establish one IKEv2 SA with a
// single ranet-provisioned strongSwan node: raw Ed25519 pubkey auth (RFC
// 7427, ASN1_DN identity), 0.0.0.0/0::/0 tunnel-mode Child SA, forced UDP
// encapsulation. See ike/const.go for the modern-only crypto this offers.
type PeerConfig struct {
	Organization string

	LocalCommonName string
	LocalSerial     string
	LocalPrivateKey ed25519.PrivateKey

	RemoteCommonName   string
	RemoteOrganization string // empty defaults to Organization
	RemoteSerial       string
	RemotePublicKey    ed25519.PublicKey

	LocalAddr  net.IP // "" => wildcard
	LocalPort  int    // 0 => ephemeral
	RemoteAddr net.IP
	RemotePort int // ranet registry endpoint port (often non-standard, e.g. 13000); the only port ever used, IKE and ESP alike
	Hub        *transport.Hub

	ChildRekeyInterval time.Duration
	IKERekeyInterval   time.Duration
	RekeyMargin        time.Duration
	RekeyJitter        time.Duration
	RekeyRetryInitial  time.Duration
	RekeyRetryMax      time.Duration
}

// ChildSA is the negotiated ESP keying material and parameters handed to
// the esp package after a successful handshake.
type ChildSA = esp.ChildSA

// ikeContext contains the state bound to one IKE SA's SPI pair. During an IKE
// SA rekey, Session keeps the replaced context until its transition completes.
type ikeContext struct {
	suite     SASuite
	skD       []byte
	skei      []byte
	sker      []byte
	skpi      []byte
	skpr      []byte
	spiI      uint64
	spiR      uint64
	responder bool // local endpoint is the responder for this IKE SA
	sendIV    atomic.Uint64

	// localMIDMu guards nextLocalMID across the whole allocate-send-consume
	// step. Run allocates there on its own goroutine while a caller tearing
	// the session down can be sending a Delete directly, and requestMu does
	// not serialize the two: it orders callers queueing work for Run, not Run
	// itself.
	localMIDMu         sync.Mutex
	nextLocalMID       uint32 // next Message ID we allocate for a local request
	nextPeerMID        uint32 // next Message ID expected from a peer request
	lastPeerResponseID uint32
	lastPeerResponse   []byte
}

// Session is an established IKE SA: it owns the shared UDP mux and can
// still service the peer's INFORMATIONAL exchanges (DPD liveness checks,
// deletes) for as long as the ESP Child SA is in use.
type Session struct {
	mux     *transport.Mux
	stateMu sync.RWMutex
	current *ikeContext
	old     *ikeContext
	// collision retains a peer-initiated candidate that a simultaneous rekey
	// decided against: the losing one until the local rekey exchange can
	// delete it, or the peer's own losing one until the peer deletes it. The
	// normal current/old pair retains the winning candidate and the SA it
	// replaces.
	collision *ikeContext
	// oldBy and collisionBy bound how long each waits for the peer's Delete.
	oldBy         time.Time
	collisionBy   time.Time
	localRekey    *ikeRekey
	ikeRekeyNonce func([]byte) error

	requestMu sync.Mutex // IKEv2 permits only one outstanding local request.
	requests  chan *localRequest

	childMu  sync.RWMutex
	Child    ChildSA
	retiring ChildSA
	// retiringBy bounds how long the replaced SA waits for the peer's Delete.
	retiringBy time.Time
	// Run expires replaced inbound SAs after an overlap period, allowing
	// queued and reordered ESP to finish after the Delete acknowledgment.
	retired          []childRetirement
	childRetireDelay time.Duration

	handlerMu     sync.RWMutex
	onChild       func(ChildSA) error
	onRetire      func(uint32) error
	trafficSeen   atomic.Bool
	childRekeying atomic.Bool
	// serving is true while Run is draining the request queue. Nothing else
	// drains it, so a local exchange started when this is false would wait out
	// its caller's patience and send nothing.
	serving atomic.Bool
	// started fixes the origin lastActive is measured from. It is written
	// once, before the session is handed to anyone.
	started time.Time
	// lastActive is how long after started the peer last proved it is still
	// there, in nanoseconds, plus one so that zero still reads as never: the
	// moment the SA was established, then every piece of authenticated
	// traffic and every answered exchange after it.
	//
	// An offset rather than a wall timestamp, because Active compares it
	// against a window of seconds. A wall clock that steps further than that,
	// which a laptop waking, an NTP correction at boot or a VM resuming all
	// do, would otherwise flip every session on the node at once: forward, all
	// of them read dead and tear down together; backward, all of them read
	// alive until the clock catches up.
	lastActive atomic.Int64
	// lastPeerChildRekey is when the last peer-initiated Child SA rekey was
	// accepted, on the same clock and with the same plus-one as lastActive.
	lastPeerChildRekey atomic.Int64

	childRekeyInterval time.Duration
	ikeRekeyInterval   time.Duration
	rekeyMargin        time.Duration
	rekeyJitter        time.Duration
	rekeyRetryInitial  time.Duration
	rekeyRetryMax      time.Duration
	rekeyJitterSource  func(time.Duration) (time.Duration, error)
}

type ikeRekey struct {
	old               *ikeContext
	nonce             []byte
	peerNonce         []byte
	peerResponseNonce []byte
}

func (s *Session) Mux() *transport.Mux { return s.mux }

func (s *Session) contexts() (current, old *ikeContext) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.current, s.old
}

func (s *Session) currentContext() *ikeContext {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return s.current
}

func (s *Session) nextPeerMessageID(ctx *ikeContext) uint32 {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return ctx.nextPeerMID
}

// retainedContextDeadline bounds how long a replaced or redundant IKE SA is
// held for the peer's Delete. RFC 7296 section 2.8.2 makes that Delete a
// SHOULD, and handleIKERekey answers every peer-initiated rekey with
// TEMPORARY_FAILURE while either is set, so a peer that rekeys once and never
// sends the Delete would refuse every later rekey for the life of the session,
// which is what retirementDeadline already stops for a Child SA. It sits above
// the 62 second retransmission budget of one exchange, so a Delete still in
// flight is not answered by a session that has already forgotten the SA.
const retainedContextDeadline = 2 * time.Minute

// retainOldLocked keeps the SA a rekey replaced reachable for the peer's
// Delete. It must be called with stateMu held.
func (s *Session) retainOldLocked(ctx *ikeContext) {
	s.old, s.oldBy = ctx, time.Now().Add(retainedContextDeadline)
}

// retainCollisionLocked does the same for the candidate a simultaneous rekey
// decided against. It must be called with stateMu held.
func (s *Session) retainCollisionLocked(ctx *ikeContext) {
	s.collision, s.collisionBy = ctx, time.Now().Add(retainedContextDeadline)
}

// expireRetainedContexts drops a retained IKE SA whose Delete never arrived.
// Its SPI leaves the mux with it, so a later datagram naming it is answered
// the way any other unknown SA is.
func (s *Session) expireRetainedContexts(now time.Time) {
	s.stateMu.Lock()
	var dropped []*ikeContext
	// An undated context is dated here rather than dropped: the zero time
	// means the deadline has not been set yet, not that it has passed.
	for _, held := range []struct {
		ctx *ikeContext
		by  *time.Time
		out **ikeContext
	}{{s.old, &s.oldBy, &s.old}, {s.collision, &s.collisionBy, &s.collision}} {
		switch {
		case held.ctx == nil:
		case held.by.IsZero():
			*held.by = now.Add(retainedContextDeadline)
		case !now.Before(*held.by):
			dropped, *held.out = append(dropped, held.ctx), nil
		}
	}
	s.stateMu.Unlock()
	for _, ctx := range dropped {
		slog.Warn("ike dropping an IKE SA the peer never deleted",
			"spi", ctx.spiI, "after", retainedContextDeadline)
		s.mux.UnregisterIKE(ctx.spiI)
	}
}

// nextRetainedExpiry is when the earliest retained IKE SA may be dropped, so
// the control loop can wait for it rather than poll for it.
func (s *Session) nextRetainedExpiry() (time.Time, bool) {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	var earliest time.Time
	if s.old != nil {
		earliest = s.oldBy
	}
	if s.collision != nil && !s.collisionBy.IsZero() && (earliest.IsZero() || s.collisionBy.Before(earliest)) {
		earliest = s.collisionBy
	}
	return earliest, !earliest.IsZero()
}

func (s *Session) removeRetainedContext(ctx *ikeContext) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if s.old == ctx {
		s.old = nil
		return true
	}
	if s.collision == ctx {
		s.collision = nil
		return true
	}
	return false
}

// adoptCollisionOnPeerDelete is the second half of RFC 7296 section 2.8.2:
// "If the peer that did notice the simultaneous rekey gets the delete request
// from the other peer for the old IKE SA, it knows that the other peer did not
// detect the simultaneous rekey, and the first peer can forget its own rekey
// attempt." The peer's new SA is the candidate already held as the loser of a
// collision only this end saw, so it becomes current. Without this the Delete
// matches no retained context and closes a session the peer believes is fine,
// and the window is not microseconds: localRekey is set before the request
// goes out, so any exchange already pending widens it to that exchange's whole
// lifetime.
func (s *Session) adoptCollisionOnPeerDelete(ctx *ikeContext) bool {
	s.stateMu.Lock()
	defer s.stateMu.Unlock()
	if ctx != s.current || s.collision == nil || s.localRekey == nil {
		return false
	}
	s.current, s.collision, s.localRekey = s.collision, nil, nil
	return true
}

// contextRetired reports an IKE SA this session no longer holds in any role.
func (s *Session) contextRetired(ctx *ikeContext) bool {
	s.stateMu.RLock()
	defer s.stateMu.RUnlock()
	return ctx != s.current && ctx != s.old && ctx != s.collision
}

// SetRekeyIntervals configures optional periodic Child and IKE SA rekeys.
// Zero disables an interval. It must be called before Run.
func (s *Session) SetRekeyIntervals(child, ike time.Duration) error {
	if child < 0 || ike < 0 {
		return fmt.Errorf("ike: rekey intervals must be nonnegative when set")
	}
	if !validRekeyTiming(child, s.rekeyMargin, s.rekeyJitter) || !validRekeyTiming(ike, s.rekeyMargin, s.rekeyJitter) {
		return fmt.Errorf("ike: rekey margin plus jitter must be less than each enabled interval")
	}
	s.childRekeyInterval = child
	s.ikeRekeyInterval = ike
	return nil
}

// SetRekeyTiming configures when scheduled rekeys run relative to their
// intervals. Zero intervals remain disabled.
func (s *Session) SetRekeyTiming(margin, jitter time.Duration) error {
	if margin < 0 || jitter < 0 {
		return fmt.Errorf("ike: rekey margin and jitter must be nonnegative")
	}
	if !validRekeyTiming(s.childRekeyInterval, margin, jitter) || !validRekeyTiming(s.ikeRekeyInterval, margin, jitter) {
		return fmt.Errorf("ike: rekey margin plus jitter must be less than each enabled interval")
	}
	s.rekeyMargin = margin
	s.rekeyJitter = jitter
	return nil
}

// SetRekeyRetry configures the capped exponential backoff after a scheduled
// rekey failure. It must be called before Run.
func (s *Session) SetRekeyRetry(initial, max time.Duration) error {
	if initial <= 0 || max <= 0 {
		return fmt.Errorf("ike: rekey retry delays must be positive")
	}
	if initial > max {
		return fmt.Errorf("ike: initial rekey retry delay must not exceed maximum")
	}
	s.rekeyRetryInitial = initial
	s.rekeyRetryMax = max
	return nil
}

func validRekeyTiming(interval, margin, jitter time.Duration) bool {
	return interval == 0 || (margin < interval && jitter < interval-margin)
}

// NoteTraffic records successfully authenticated ESP traffic for the DPD
// policy. RFC 7296 section 2.4 treats it as proof that the IKE SA is alive.
// Run consumes this edge the next time it wakes, so the data plane pays an
// atomic store rather than a clock read per packet.
func (s *Session) NoteTraffic() { s.trafficSeen.Store(true) }

const (
	requestTimeout = 2 * time.Second
	maxRetransmits = 5
	// maxRetransmitsWhileBusy bounds an exchange the peer keeps alive without
	// answering. The backoff is clamped at requestTimeout<<(maxRetransmits-1),
	// which is thirty-two seconds, so twenty sends is about nine minutes.
	maxRetransmitsWhileBusy = 20
	// RFC 7296 section 2.6 bounds a cookie to 1..64 octets.
	maxCookieLength = 64
)

func randUint64Nonzero() uint64 {
	for {
		var b [8]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint64(b[:])
		if v != 0 {
			return v
		}
	}
}

func randUint32Nonzero() uint32 {
	for {
		var b [4]byte
		rand.Read(b[:])
		v := binary.BigEndian.Uint32(b[:])
		if v > 255 {
			return v
		}
	}
}

// ikeProposal is the single modern-crypto-only IKE SA proposal we offer:
// AES-256/128-GCM or ChaCha20-Poly1305, PRF-HMAC-SHA-384/256, and
// Curve25519/P-384/P-256. No legacy transforms, no separate integrity
// transform (all offered ciphers are AEAD).
func ikeProposal() Proposal {
	return Proposal{
		Number:   1,
		Protocol: ProtoIKE,
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_384},
			{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			{Type: TransDH, ID: DH_CURVE25519},
			{Type: TransDH, ID: DH_ECP_384},
			{Type: TransDH, ID: DH_ECP_256},
		},
	}
}

func espProposal(spi []byte) Proposal {
	return Proposal{
		Number:   1,
		Protocol: ProtoESP,
		SPI:      spi,
		Transforms: []Transform{
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305},
			{Type: TransESN, ID: ESN_NO},
		},
	}
}

// Initiate runs IKE_SA_INIT then IKE_AUTH against cfg.RemoteAddr:RemotePort
// and returns an established Session with one Child SA. It implements
// exactly RFC 7815's minimal-initiator surface plus what ranet's
// strongSwan deployments require: raw Ed25519 signature auth and
// unconditional UDP encapsulation on that one explicit port — every IKE
// message, from IKE_SA_INIT onward, carries the non-ESP marker; there is
// no NAT-T floating to a separate port, certificates, EAP, or MOBIKE.
func Initiate(cfg PeerConfig) (*Session, error) {
	return InitiateContext(context.Background(), cfg)
}

// InitiateContext cancels only the handshake's mux. It does not close a shared
// hub or bind the established session's lifetime to ctx; Session.Run owns that.
func InitiateContext(ctx context.Context, cfg PeerConfig) (session *Session, err error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	local := ""
	if cfg.LocalAddr != nil {
		local = cfg.LocalAddr.String()
	}
	local = net.JoinHostPort(local, fmt.Sprint(cfg.LocalPort))

	var mux *transport.Mux
	if cfg.Hub != nil {
		mux, err = cfg.Hub.NewMux(cfg.RemoteAddr, cfg.RemotePort)
	} else {
		mux, err = transport.Dial(local, cfg.RemoteAddr, cfg.RemotePort)
	}
	if err != nil {
		return nil, err
	}

	stopCancel := context.AfterFunc(ctx, func() { _ = mux.Close() })
	defer func() {
		stopCancel()
		if ctx.Err() != nil {
			_ = mux.Close()
			session, err = nil, ctx.Err()
		}
	}()

	spiI := randUint64Nonzero()
	group := uint16(DH_CURVE25519)

	var (
		req     []byte
		respRaw []byte
		resp    *Message
		dh      *DHKeyPair
		ni      []byte
	)

	// Two unauthenticated responses can send us round again. The responder may
	// reject our preferred DH group with N(INVALID_KE_PAYLOAD, desired-group),
	// and under load it may answer N(COOKIE) instead of allocating state
	// (RFC 7296 §2.6). Each is allowed once, so the loop is bounded whatever
	// the far end does.
	var (
		cookie        []byte
		cookieRetried bool
		groupRetried  bool
	)
	// Hashed once, outside the loop. RFC 7296 section 2.6 requires a cookie
	// retry to carry "all other payloads unchanged", and a responder that
	// folds the request into its cookie rejects a retry that moved this,
	// handing out a fresh challenge every time.
	var fakeAddr [4]byte
	rand.Read(fakeAddr[:])
	srcHash := natDetectionHash(spiI, 0, net.IP(fakeAddr[:]), 0)
	for {
		if dh == nil {
			dh, err = GenerateDH(group)
			if err != nil {
				mux.Close()
				return nil, err
			}
		}
		if ni == nil {
			// The nonce stays fixed for the whole exchange. A cookie is a
			// keyed hash of it together with our SPI and address, so a retry
			// that regenerated it would be handed a fresh challenge forever.
			ni = make([]byte, 32)
			rand.Read(ni)
		}

		hdr := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
		hashAlgos := make([]byte, 2)
		binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
		payloads := []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
			{Type: PayloadKE, Body: EncodeKE(group, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		}
		// NAT_DETECTION_SOURCE_IP, RFC 7296 §2.23. Without this notify,
		// the responder has nothing to compare against for our side and
		// apparently doesn't treat the connection as NAT'd even with
		// encap=yes configured — confirmed by inspecting the resulting
		// kernel XFRM state (`ip xfrm state`), which had no `encap` info
		// attached at all, causing every inbound ESP packet to be
		// silently dropped at the kernel's encap_type check
		// (net/xfrm/xfrm_input.c) before authentication is even
		// attempted. strongSwan's own initiator (ike_natd.c,
		// build_natd_payload) handles this identically when force_encap
		// is set: rather than using its real local address (which would
		// only force NAT-T if it happens to mismatch what the responder
		// observes), it hashes a random IPv4 address with port 0,
		// guaranteeing a mismatch so NAT is always assumed — do the same
		// here rather than relying on whatever this socket's wildcard
		// bind address happens to be.
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_SOURCE_IP, Data: srcHash})})
		dstHash := natDetectionHash(spiI, 0, cfg.RemoteAddr, uint16(cfg.RemotePort))
		payloads = append(payloads, RawPayload{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_DESTINATION_IP, Data: dstHash})})

		if cookie != nil {
			// RFC 7296 §2.6: "include the COOKIE notification containing the
			// received data as the first payload, and all other payloads
			// unchanged".
			payloads = append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: cookie})}}, payloads...)
		}

		m := &Message{Header: hdr, Payloads: payloads}
		req = m.Encode()

		// A bare notify-only response is only worth stopping for when it's
		// N_INVALID_KE_PAYLOAD on the first attempt -- the one legitimate
		// signal that lets us make progress by switching Diffie-Hellman
		// group. Anything else unauthenticated (see sendRecv's doc comment)
		// is rejected here, which makes sendRecv keep retransmitting/
		// waiting for the real response instead of surfacing a possibly
		// forged error.
		haveCookie, haveGroup := cookieRetried, groupRetried
		respRaw, err = sendRecv(mux, req, func(raw []byte) bool {
			m, err := DecodeMessage(raw)
			if err != nil {
				return false
			}
			if m.find(PayloadSA) != nil {
				return true
			}
			_, ok := usefulInitNotify(m, haveCookie, haveGroup)
			return ok
		})
		if err != nil {
			mux.Close()
			return nil, err
		}
		resp, err = DecodeMessage(respRaw)
		if err != nil {
			mux.Close()
			return nil, fmt.Errorf("ike: decode IKE_SA_INIT response: %w", err)
		}
		if resp.find(PayloadSA) != nil {
			break
		}
		// Only reachable for the notify accept() just validated.
		notify, _ := usefulInitNotify(resp, haveCookie, haveGroup)
		switch notify.Type {
		case N_COOKIE:
			// Everything else about the request stays as it was, so dh and ni
			// are deliberately not regenerated here.
			cookie, cookieRetried = notify.Data, true
		case N_INVALID_KE_PAYLOAD:
			group, groupRetried, dh = binary.BigEndian.Uint16(notify.Data[:2]), true, nil
		}
	}
	if err := validateResponseCriticalFlags(resp.Payloads); err != nil {
		mux.Close()
		return nil, err
	}

	spiR := resp.Header.SPIResponder
	supportsIdentity, err := supportsSignatureHash(resp.Payloads, HashIdentity)
	if err != nil {
		mux.Close()
		return nil, err
	}
	if !supportsIdentity {
		mux.Close()
		return nil, fmt.Errorf("ike: responder did not advertise Ed25519 Identity hash support")
	}
	saPl := resp.find(PayloadSA)
	kePl := resp.find(PayloadKE)
	noncePl := resp.find(PayloadNonce)
	if saPl == nil || kePl == nil || noncePl == nil {
		mux.Close()
		return nil, fmt.Errorf("ike: incomplete IKE_SA_INIT response")
	}
	props, err := DecodeSA(saPl.Body)
	if err != nil || len(props) != 1 {
		mux.Close()
		return nil, fmt.Errorf("ike: bad SA in IKE_SA_INIT response: %v", err)
	}
	suite, err := suiteFromProposal(props[0])
	if err != nil {
		mux.Close()
		return nil, err
	}
	peerGroup, peerPub, err := DecodeKE(kePl.Body)
	if err != nil || peerGroup != group || peerGroup != suite.DHGroup {
		mux.Close()
		return nil, fmt.Errorf("ike: KE group mismatch (got %d, used %d)", peerGroup, group)
	}
	nr := DecodeNonce(noncePl.Body)
	if !validNonceFor(nr, suite.PRFID) {
		mux.Close()
		return nil, fmt.Errorf("ike: responder nonce length %d is short for the negotiated PRF", len(nr))
	}

	shared, err := dh.SharedSecret(peerPub)
	if err != nil {
		mux.Close()
		return nil, err
	}
	keys, err := DeriveIKEKeys(suite, shared, ni, nr, spiI, spiR)
	if err != nil {
		mux.Close()
		return nil, err
	}

	sess := &Session{
		started:          time.Now(),
		childRetireDelay: 5 * time.Second,
		mux:              mux,
		current: &ikeContext{suite: suite,
			skD: keys.SKd, skei: keys.SKei, sker: keys.SKer, skpi: keys.SKpi, skpr: keys.SKpr,
			spiI: spiI, spiR: spiR, nextLocalMID: 2},
		requests: make(chan *localRequest, 1),
	}
	if err := sess.completeIKEAuth(cfg, req, respRaw, ni, nr); err != nil {
		mux.Close()
		return nil, err
	}
	if err := sess.SetRekeyTiming(cfg.RekeyMargin, cfg.RekeyJitter); err != nil {
		mux.Close()
		return nil, err
	}
	if err := sess.SetRekeyIntervals(cfg.ChildRekeyInterval, cfg.IKERekeyInterval); err != nil {
		mux.Close()
		return nil, err
	}
	if cfg.RekeyRetryInitial == 0 && cfg.RekeyRetryMax == 0 {
		cfg.RekeyRetryInitial = 5 * time.Second
		cfg.RekeyRetryMax = 5 * time.Minute
	}
	if err := sess.SetRekeyRetry(cfg.RekeyRetryInitial, cfg.RekeyRetryMax); err != nil {
		mux.Close()
		return nil, err
	}
	sess.noteEstablished()
	return sess, nil
}

func supportsSignatureHash(payloads []RawPayload, wanted uint16) (bool, error) {
	found := false
	for _, payload := range payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			return false, err
		}
		if notify.Type != N_SIGNATURE_HASH_ALGORITHMS {
			continue
		}
		if len(notify.Data) == 0 || len(notify.Data)%2 != 0 {
			return false, fmt.Errorf("ike: malformed signature hash algorithms notification")
		}
		for i := 0; i < len(notify.Data); i += 2 {
			if binary.BigEndian.Uint16(notify.Data[i:i+2]) == wanted {
				found = true
			}
		}
	}
	return found, nil
}

func suiteFromProposal(p Proposal) (SASuite, error) {
	// Three transforms decide keys, and a responder that took an integrity
	// transform we offered has to return it, RFC 7296 section 2.7, so four is
	// a shape this end has to be able to read even though it never offers one.
	if p.Number != 1 || p.Protocol != ProtoIKE || len(p.SPI) != 0 || len(p.Transforms) < 3 || len(p.Transforms) > 4 {
		return SASuite{}, fmt.Errorf("ike: invalid selected IKE proposal shape")
	}
	offered := ikeProposal().Transforms
	selected := make(map[TransformType]Transform, 3)
	for _, transform := range p.Transforms {
		if transform.Type == TransInteg && transform.ID == INTEG_NONE && !transform.UnsupportedAttributes {
			continue
		}
		if transform.Type != TransEncr && transform.Type != TransPRF && transform.Type != TransDH {
			return SASuite{}, fmt.Errorf("ike: unexpected selected transform type %d", transform.Type)
		}
		if _, duplicate := selected[transform.Type]; duplicate {
			return SASuite{}, fmt.Errorf("ike: duplicate selected transform type %d", transform.Type)
		}
		matched := false
		for _, candidate := range offered {
			if transform == candidate {
				matched = true
				break
			}
		}
		if !matched {
			return SASuite{}, fmt.Errorf("ike: responder selected unoffered transform %d/%d", transform.Type, transform.ID)
		}
		selected[transform.Type] = transform
	}
	encr, encrOK := selected[TransEncr]
	prfT, prfOK := selected[TransPRF]
	dhT, dhOK := selected[TransDH]
	if !encrOK || !prfOK || !dhOK {
		return SASuite{}, fmt.Errorf("ike: incomplete selected IKE proposal")
	}
	// The key length is the transform's own: ChaCha20-Poly1305 carries no
	// KEY_LENGTH attribute, which canonicalEncryptionTransform enforces, and
	// aeadParams reads its fixed 32 bytes from the cipher rather than from
	// here. Substituting 256 named a number the wire never carried.
	return SASuite{EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits, PRFID: prfT.ID, DHGroup: dhT.ID}, nil
}

func (s *Session) completeIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte) error {
	authenticated, err := s.doIKEAuth(cfg, realMessage1, realMessage2, ni, nr)
	if err == nil || !authenticated {
		return err
	}

	// RFC 7296 §2.21.2 says a valid responder AUTH establishes the IKE SA
	// even when the Child SA creation bundled into IKE_AUTH fails, and leaves
	// deleting it to the initiator's policy. ranet cannot use an IKE SA
	// without that Child SA, so close the authenticated SA with a normal
	// encrypted IKE Delete before returning the Child negotiation error.
	if deleteErr := s.deleteAuthenticatedIKE(); deleteErr != nil {
		return fmt.Errorf("%w; additionally failed to delete authenticated IKE SA: %v", err, deleteErr)
	}
	return err
}

// teardownRetransmits bounds the Delete that closes an IKE SA this end
// authenticated and cannot use. RFC 7296 section 2.21.2 leaves the IKE SA
// created when only the Child SA bundled into IKE_AUTH fails and says the
// initiator "MAY, of course, for reasons of policy later delete such an IKE
// SA", which is this fork's policy: it has no use for an IKE SA without that
// Child SA. Nothing here depends on the answer, and the ordinary reason for
// silence is that the responder discarded the SA first, which is what it does
// in exactly this case. Spending the full budget delayed the dial's failure by
// sixty-two seconds for a result the response had already named.
const teardownRetransmits = 2

func (s *Session) deleteAuthenticatedIKE() error {
	ctx := s.current
	flags := uint8(0)
	if !ctx.responder {
		flags = FlagInitiator
	}
	hdr := Header{
		SPIInitiator: ctx.spiI,
		SPIResponder: ctx.spiR,
		ExchangeType: INFORMATIONAL,
		Flags:        flags,
		MessageID:    ctx.nextLocalMID,
	}
	req, err := ctx.encrypt(ctx.localEncryptionKey(), hdr, nil, []RawPayload{{
		Type: PayloadD,
		Body: EncodeDelete(Delete{Protocol: ProtoIKE}),
	}})
	if err != nil {
		return fmt.Errorf("ike: build IKE Delete: %w", err)
	}
	resp, inner, err := encryptedRoundTripWithin(s.mux, ctx, req, teardownRetransmits)
	if err != nil {
		return err
	}
	if err := validateResponseCriticalFlags(resp.Payloads); err != nil {
		return err
	}
	if err := validateResponseCriticalFlags(inner); err != nil {
		return err
	}
	if len(inner) != 0 {
		return fmt.Errorf("ike: IKE Delete response is not empty")
	}
	return nil
}

func (s *Session) doIKEAuth(cfg PeerConfig, realMessage1, realMessage2, ni, nr []byte) (bool, error) {
	mySPI := randUint32Nonzero()
	spiBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(spiBuf, mySPI)

	idiBody := EncodeID(ID_DER_ASN1_DN, EncodeIdentityDN(cfg.Organization, cfg.LocalCommonName, cfg.LocalSerial))
	remoteOrganization := cfg.RemoteOrganization
	if remoteOrganization == "" {
		remoteOrganization = cfg.Organization
	}
	idrBody := EncodeID(ID_DER_ASN1_DN, EncodeIdentityDN(remoteOrganization, cfg.RemoteCommonName, cfg.RemoteSerial))

	macedIDForI := prf(s.current.suite.PRFID, s.current.skpi, idiBody)
	signedOctets := concat(realMessage1, nr, macedIDForI)
	authBody := BuildAuth(cfg.LocalPrivateKey, signedOctets)

	tsv4, tsv6 := FullRangeV4(), FullRangeV6()
	inner := []RawPayload{
		{Type: PayloadIDi, Body: idiBody},
		{Type: PayloadIDr, Body: idrBody},
		{Type: PayloadAUTH, Body: authBody},
		{Type: PayloadSA, Body: EncodeSA([]Proposal{espProposal(spiBuf)})},
		{Type: PayloadTSi, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
		{Type: PayloadTSr, Body: EncodeTS([]TrafficSelector{tsv4, tsv6})},
	}
	hdr := Header{SPIInitiator: s.current.spiI, SPIResponder: s.current.spiR, ExchangeType: IKE_AUTH, Flags: FlagInitiator, MessageID: 1}
	req, err := s.current.encrypt(s.current.skei, hdr, nil, inner)
	if err != nil {
		return false, err
	}

	resp, respInner, err := encryptedRoundTrip(s.mux, s.current, req)
	if err != nil {
		return false, err
	}
	if err := validateResponseCriticalFlags(resp.Payloads); err != nil {
		return false, err
	}
	if err := validateResponseCriticalFlags(respInner); err != nil {
		return false, err
	}
	respMsg := &Message{Header: resp.Header, Payloads: respInner}

	idrRecv := respMsg.find(PayloadIDr)
	authRecv := respMsg.find(PayloadAUTH)
	saRecv := respMsg.find(PayloadSA)
	tsiRecv := respMsg.find(PayloadTSi)
	tsrRecv := respMsg.find(PayloadTSr)
	if idrRecv == nil || authRecv == nil {
		if n := respMsg.find(PayloadN); n != nil {
			nt, err := DecodeNotify(n.Body)
			if err != nil {
				return false, err
			}
			return false, fmt.Errorf("ike: IKE_AUTH rejected inside SK: notify type %d", nt.Type)
		}
		return false, fmt.Errorf("ike: incomplete IKE_AUTH response")
	}
	macedIDForR := prf(s.current.suite.PRFID, s.current.skpr, idrRecv.Body)
	responderSigned := concat(realMessage2, ni, macedIDForR)
	if err := VerifyAuth(cfg.RemotePublicKey, responderSigned, authRecv.Body); err != nil {
		return false, err
	}
	// Compare the name rather than the bytes: ranet writes O and CN as
	// UTF8String while strongSwan picks the string type from the value, so
	// one identity legitimately reaches the wire in two encodings. AUTH above
	// already signed the bytes as received, so the name is all that is left
	// to check.
	got, err := identityFromID(idrRecv.Body)
	if err != nil {
		return false, err
	}
	if got != (Identity{Organization: remoteOrganization, CommonName: cfg.RemoteCommonName, SerialNumber: cfg.RemoteSerial}) {
		return false, fmt.Errorf("ike: responder identity %s does not match configured IDr", got)
	}

	// Only after verifying AUTH may Child-SA failures be authoritative. Per
	// RFC 7296 §2.21.2, the IKE SA is now authenticated independently of the
	// success or failure of the Child SA negotiation below.
	if saRecv == nil {
		if n := respMsg.find(PayloadN); n != nil {
			nt, err := DecodeNotify(n.Body)
			if err != nil {
				return true, err
			}
			return true, fmt.Errorf("ike: Child SA rejected: notify type %d", nt.Type)
		}
	}
	if saRecv == nil || tsiRecv == nil || tsrRecv == nil {
		return true, fmt.Errorf("ike: incomplete IKE_AUTH response")
	}
	if err := validateFullRangeSelectors(tsiRecv, tsrRecv); err != nil {
		return true, err
	}

	_, encr, remoteSPI, err := decodeChildProposal(saRecv.Body, nil)
	if err != nil {
		return true, fmt.Errorf("ike: bad child SA in IKE_AUTH response: %w", err)
	}

	initKey, respKey, err := ChildSAKeymat(s.current.suite.PRFID, s.current.skD, ni, nr, encr.ID, encr.KeyLengthBits)
	if err != nil {
		return true, err
	}
	if err := s.replaceChild(ChildSA{
		EncrID: encr.ID, EncrKeyBits: encr.KeyLengthBits,
		LocalSPI: mySPI, RemoteSPI: remoteSPI,
		InboundKey: respKey, OutboundKey: initKey,
	}); err != nil {
		return true, err
	}
	return true, nil
}

// usefulInitNotify finds the one unauthenticated IKE_SA_INIT notify worth
// acting on. Only two let the exchange make progress, each once: N(COOKIE)
// asks us to prove return routability (RFC 7296 §2.6) and
// N(INVALID_KE_PAYLOAD) names a Diffie-Hellman group the responder will take
// (§1.2). Everything else unauthenticated is ignored, so sendRecv keeps
// waiting for the real response rather than letting anyone who can spoof our
// SPI abort the handshake.
func usefulInitNotify(m *Message, cookieUsed, groupUsed bool) (Notify, bool) {
	for _, payload := range m.Payloads {
		if payload.Type != PayloadN {
			continue
		}
		notify, err := DecodeNotify(payload.Body)
		if err != nil {
			continue
		}
		switch {
		case notify.Type == N_COOKIE && !cookieUsed:
			// RFC 7296 section 2.6: "The data associated with this
			// notification MUST be between 1 and 64 octets in length". Echoing
			// whatever arrives would let anyone who can see our SPI turn one
			// spoofed datagram into five oversized ones aimed at our peer.
			if len(notify.Data) == 0 || len(notify.Data) > maxCookieLength {
				continue
			}
			return notify, true
		case notify.Type == N_INVALID_KE_PAYLOAD && !groupUsed && len(notify.Data) >= 2:
			// A group we cannot generate aborts the dial with no retry, so an
			// unauthenticated notify naming one would end the handshake.
			if !supportedIKEGroup(binary.BigEndian.Uint16(notify.Data[:2])) {
				continue
			}
			return notify, true
		}
	}
	return Notify{}, false
}

// Active reports whether this session has recently proved the peer is still
// there. A session that is merely installed proves nothing: after a peer
// reboots, the SA on this side stays in place, looking established, until dead
// peer detection reaps it a minute or more later.
//
// A freshly established SA counts as active without having carried anything
// yet, because a handshake that just completed is the same proof. Deciding
// from Run instead would make a session read as dead for as long as it takes
// its own control loop to start, and two nodes resolving a simultaneous open
// in that window could keep different sessions.
func (s *Session) Active() bool {
	last := s.lastActive.Load()
	return last != 0 && time.Since(s.started)-time.Duration(last-1) < 2*dpdInterval
}

// noteActive records that the peer has just proved it is still there.
func (s *Session) noteActive() { s.lastActive.Store(int64(time.Since(s.started)) + 1) }

// minPeerChildRekeyInterval is the shortest gap between accepted
// peer-initiated Child SA rekeys. Each one retains the SA it replaces for the
// retirement delay, and installing a replacement copies the retained set, so a
// peer rekeying as fast as it can drives that set to its own rate times the
// delay and makes every install proportional to it. A legitimate rekey is
// minutes apart: the packet-count trigger fires once per sequence space and
// the scheduled one once per interval.
const minPeerChildRekeyInterval = time.Second

// allowPeerChildRekey reports whether to take on another peer-initiated Child
// SA rekey, and records it when it does.
func (s *Session) allowPeerChildRekey() bool {
	now := int64(time.Since(s.started))
	if last := s.lastPeerChildRekey.Load(); last != 0 && now-(last-1) < int64(minPeerChildRekeyInterval) {
		return false
	}
	s.lastPeerChildRekey.Store(now + 1)
	return true
}

// noteEstablished starts the liveness clock at the end of the handshake.
func (s *Session) noteEstablished() { s.noteActive() }
