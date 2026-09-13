package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"net"
	"slices"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

type responderHarness struct {
	responder  *Responder
	initiator  *transport.Hub
	remotePort int
	public     ed25519.PublicKey
	private    ed25519.PrivateKey
	sessions   chan *Session
	identities chan Accepted
}

// newResponderHarness runs a Responder on one hub and hands back everything
// needed to dial it from another, so a handshake in these tests is a real
// exchange over loopback rather than hand-built messages.
func newResponderHarness(t *testing.T, lookup func(Identity) (ed25519.PublicKey, bool)) *responderHarness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responderHub, err := transport.NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { responderHub.Close() })
	initiatorHub, err := transport.NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { initiatorHub.Close() })

	local := Identity{Organization: "testorg", CommonName: "server", SerialNumber: "1"}
	if lookup == nil {
		lookup = func(id Identity) (ed25519.PublicKey, bool) {
			return public, id == Identity{Organization: "testorg", CommonName: "client", SerialNumber: "2"}
		}
	}
	responder, err := NewResponder(ResponderConfig{
		Hub:              responderHub,
		Local:            []Identity{local},
		LocalPrivateKey:  private,
		Lookup:           lookup,
		HandshakeTimeout: 10 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	h := &responderHarness{
		responder:  responder,
		initiator:  initiatorHub,
		remotePort: responderHub.LocalAddr().(*net.UDPAddr).Port,
		public:     public,
		private:    private,
		sessions:   make(chan *Session, 1),
		identities: make(chan Accepted, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go responder.Serve(ctx, func(s *Session, accepted Accepted) {
		h.sessions <- s
		h.identities <- accepted
	})
	return h
}

func (h *responderHarness) dial(t *testing.T) (*Session, error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return InitiateContext(ctx, PeerConfig{
		Organization:     "testorg",
		LocalCommonName:  "client",
		LocalSerial:      "2",
		LocalPrivateKey:  h.private,
		RemoteCommonName: "server",
		RemoteSerial:     "1",
		RemotePublicKey:  h.public,
		RemoteAddr:       net.ParseIP("127.0.0.1"),
		RemotePort:       h.remotePort,
		Hub:              h.initiator,
	})
}

// Two ranet-lite nodes could never reach each other before the responder
// existed, so this is the case the whole feature is for.
func TestResponderCompletesHandshakeWithInitiator(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()

	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("responder produced no session")
	}
	defer responder.Mux().Close()

	accepted := <-h.identities
	if accepted.Peer != (Identity{Organization: "testorg", CommonName: "client", SerialNumber: "2"}) {
		t.Fatalf("authenticated identity = %s", accepted.Peer)
	}
	if accepted.Local != (Identity{Organization: "testorg", CommonName: "server", SerialNumber: "1"}) {
		t.Fatalf("local identity = %s", accepted.Local)
	}
	// Each side's outbound key must be the other's inbound key, or the first
	// ESP packet decrypts to nothing on a tunnel both ends believe is up.
	if !bytes.Equal(initiator.Child.OutboundKey, responder.Child.InboundKey) {
		t.Error("initiator outbound key does not match responder inbound key")
	}
	if !bytes.Equal(initiator.Child.InboundKey, responder.Child.OutboundKey) {
		t.Error("responder outbound key does not match initiator inbound key")
	}
	if initiator.Child.LocalSPI != responder.Child.RemoteSPI || initiator.Child.RemoteSPI != responder.Child.LocalSPI {
		t.Errorf("child SPIs do not mirror: %08x/%08x against %08x/%08x",
			initiator.Child.LocalSPI, initiator.Child.RemoteSPI, responder.Child.LocalSPI, responder.Child.RemoteSPI)
	}
	if initiator.Child.EncrID != responder.Child.EncrID || initiator.Child.EncrKeyBits != responder.Child.EncrKeyBits {
		t.Error("the two sides selected different child encryption")
	}
	if !responder.current.responder || initiator.current.responder {
		t.Error("session roles are not what each side played")
	}
	if responder.current.nextPeerMID != 2 || responder.current.nextLocalMID != 0 {
		t.Errorf("responder message ids = peer %d, local %d; want 2 and 0",
			responder.current.nextPeerMID, responder.current.nextLocalMID)
	}
	// A retransmitted IKE_AUTH has to be answerable from Run onwards.
	if responder.current.lastPeerResponseID != 1 || len(responder.current.lastPeerResponse) == 0 {
		t.Error("responder did not retain its IKE_AUTH response for retransmission")
	}
}

func TestResponderRejectsUnknownIdentity(t *testing.T) {
	h := newResponderHarness(t, func(Identity) (ed25519.PublicKey, bool) { return nil, false })
	session, err := h.dial(t)
	if err == nil {
		session.Mux().Close()
		t.Fatal("handshake succeeded against a responder that knows no peers")
	}
	select {
	case <-h.sessions:
		t.Fatal("responder produced a session for an unknown identity")
	case <-time.After(100 * time.Millisecond):
	}
}

func TestResponderRejectsWrongKey(t *testing.T) {
	other, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	h := newResponderHarness(t, func(Identity) (ed25519.PublicKey, bool) { return other, true })
	session, err := h.dial(t)
	if err == nil {
		session.Mux().Close()
		t.Fatal("handshake succeeded with an AUTH the responder could not verify")
	}
}

func TestIdentityRoundTripsThroughItsEncoding(t *testing.T) {
	for _, id := range []Identity{
		{Organization: "testorg", CommonName: "server", SerialNumber: "1"},
		{Organization: "", CommonName: "", SerialNumber: ""},
		{Organization: "an organization long enough to need a two octet DER length, padded out to be sure", CommonName: "node", SerialNumber: "42"},
	} {
		decoded, err := identityFromID(id.encodeID())
		if err != nil {
			t.Fatalf("%s: %v", id, err)
		}
		if decoded != id {
			t.Fatalf("round trip produced %s, want %s", decoded, id)
		}
	}
}

func TestIdentityAcceptsEitherDERStringType(t *testing.T) {
	id := Identity{Organization: "testorg", CommonName: "server", SerialNumber: "1"}
	body := id.encodeID()
	// strongSwan picks the ASN.1 string type from the characters in the value
	// rather than per attribute, so it puts a printable organization in a
	// PrintableString where ranet writes a UTF8String. The two name one peer.
	printable := bytes.Replace(body, []byte{0x0c, 0x07, 't', 'e', 's', 't', 'o', 'r', 'g'}, []byte{0x13, 0x07, 't', 'e', 's', 't', 'o', 'r', 'g'}, 1)
	if bytes.Equal(printable, body) {
		t.Fatal("test did not alter the encoding")
	}
	decoded, err := identityFromID(printable)
	if err != nil {
		t.Fatalf("a PrintableString organization was rejected: %v", err)
	}
	if decoded != id {
		t.Fatalf("decoded %s, want %s", decoded, id)
	}
}

func TestIdentityRejectsAttributesThisProfileDoesNotUse(t *testing.T) {
	// An RDNSequence carrying a country or an extra common name names a peer
	// this profile cannot reason about, so it is refused rather than reduced
	// to the attributes it happens to recognize.
	extra := derSequence(
		derSet(derSequence(oidOrganizationName, derUTF8String("testorg"))),
		derSet(derSequence(oidCommonName, derUTF8String("server"))),
		derSet(derSequence(oidSerialNumber, derPrintableString("1"))),
		derSet(derSequence([]byte{0x06, 0x03, 0x55, 0x04, 0x06}, derPrintableString("FR"))),
	)
	if _, err := identityFromID(EncodeID(ID_DER_ASN1_DN, extra)); err == nil {
		t.Fatal("an identity with a fourth attribute was accepted")
	}
}

func TestIdentityAcceptsAttributesInAnyOrder(t *testing.T) {
	reordered := derSequence(
		derSet(derSequence(oidCommonName, derUTF8String("server"))),
		derSet(derSequence(oidSerialNumber, derPrintableString("1"))),
		derSet(derSequence(oidOrganizationName, derUTF8String("testorg"))),
	)
	decoded, err := identityFromID(EncodeID(ID_DER_ASN1_DN, reordered))
	if err != nil {
		t.Fatal(err)
	}
	if decoded != (Identity{Organization: "testorg", CommonName: "server", SerialNumber: "1"}) {
		t.Fatalf("decoded %s", decoded)
	}
}

func TestSelectIKEProposalPrefersOurOrderAndReportsGroup(t *testing.T) {
	offer := func(transforms ...Transform) []byte {
		return EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, Transforms: transforms}})
	}
	t.Run("prefers the stronger cipher we offer, not the peer's order", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128},
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_384},
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		_, suite, err := selectIKEProposal(body, DH_CURVE25519)
		if err != nil {
			t.Fatal(err)
		}
		if suite.EncrKeyBits != 256 || suite.PRFID != PRF_HMAC_SHA2_384 {
			t.Fatalf("selected %d-bit encryption with prf %d", suite.EncrKeyBits, suite.PRFID)
		}
	})
	t.Run("reports the group when only the KE payload is wrong", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransDH, ID: DH_ECP_256},
		)
		_, _, err := selectIKEProposal(body, DH_CURVE25519)
		var wrongGroup *invalidKEError
		if !errors.As(err, &wrongGroup) || wrongGroup.group != DH_ECP_256 {
			t.Fatalf("err = %v, want a request for group %d", err, DH_ECP_256)
		}
	})
	t.Run("rejects a proposal carrying a transform type we cannot name", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransDH, ID: DH_CURVE25519},
			Transform{Type: TransformType(9), ID: 1},
		)
		if _, _, err := selectIKEProposal(body, DH_CURVE25519); err == nil {
			t.Fatal("an unknown transform type was accepted")
		}
	})
	t.Run("rejects an offer with no cipher in common", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: 12, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		if _, _, err := selectIKEProposal(body, DH_CURVE25519); err == nil {
			t.Fatal("an offer with no shared cipher was accepted")
		}
	})
}

// The control loop used to poll its own request queue ten times a second. With
// the poll gone, a local exchange has to be picked up because the loop selects
// on the queue, not because a timer happened to fire; if that regressed, this
// would wait out the DPD interval instead.
func TestLocalRequestIsPickedUpWithoutPolling(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("responder produced no session")
	}
	defer responder.Mux().Close()
	<-h.identities

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go initiator.Run(ctx)
	go responder.Run(ctx)

	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, err := initiator.request(INFORMATIONAL, nil)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("informational exchange: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("local request was not picked up within 2s, dpd interval is %s", dpdInterval)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("local request took %s", elapsed)
	}
}

// A responder under cookie pressure is useless if the initiator cannot answer
// the challenge, and a mesh of these nodes then partitions: every dial gets
// N(COOKIE) on all its retransmissions and fails. RFC 7296 section 2.6 requires the
// initiator to retry with the cookie as its first payload.
func TestInitiatorAnswersCookieChallenge(t *testing.T) {
	h := newResponderHarness(t, nil)
	// Above the threshold every IKE_SA_INIT is challenged, which is the
	// condition an unauthenticated flood produces.
	h.responder.mu.Lock()
	h.responder.halfOpen = cookieThreshold
	h.responder.mu.Unlock()

	session, err := h.dial(t)
	if err != nil {
		t.Fatalf("a dial into a responder issuing cookies failed: %v", err)
	}
	t.Cleanup(func() { session.Mux().Close() })
	select {
	case accepted := <-h.identities:
		if accepted.Peer.CommonName != "client" {
			t.Fatalf("the responder accepted %q", accepted.Peer.CommonName)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the responder never reported the accepted session")
	}
}

// The retransmission path must not answer a datagram that merely names a live
// SPIi. Anyone who has opened an SA of their own knows one, so answering a
// bare header would turn a 28 byte datagram with a forged source address into
// the full IKE_SA_INIT response delivered wherever it pointed.
func TestResponderDoesNotReflectOnSPIAlone(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })

	request, spiI := buildTestSAInit(t)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	first, err := mux.RecvIKEUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("the responder did not answer a valid IKE_SA_INIT: %v", err)
	}
	// The session is now parked in awaitAuthRequest, which is the only place
	// the retransmission answer is reachable from.

	bare := (&Message{Header: Header{
		SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0,
	}}).Encode()
	if len(bare) >= len(request) {
		t.Fatalf("the probe is %d bytes against a %d byte request, so it would not amplify", len(bare), len(request))
	}
	if err := mux.SendIKE(bare); err != nil {
		t.Fatal(err)
	}
	if reply, err := mux.RecvIKEUntil(time.Now().Add(time.Second)); err == nil {
		t.Fatalf("a %d byte header drew a %d byte response, which is an amplifier", len(bare), len(reply))
	}

	// A real retransmission is still answered, or a lost response would strand
	// every handshake that hits one.
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	again, err := mux.RecvIKEUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("an identical retransmission was not answered: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Error("the retransmission drew a different response than the original")
	}
}

// Everything before the half-open slot is answered from the datagram alone.
// Everything after it costs a Diffie-Hellman and a key derivation, measured at
// 72 microseconds and 5 KiB a packet, which is a core saturated at fourteen
// thousand packets a second by anyone who can reach the port. The slot has to
// come before that work, not after it.
//
// The observable is the last stateless answer before the key exchange: an
// offer this responder cannot accept draws NO_PROPOSAL_CHOSEN, so receiving
// one proves execution reached selectIKEProposal. With every slot taken that
// answer must not come, because the refusal happens first.
func TestResponderTakesItsSlotBeforeTheKeyExchange(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })

	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// AES-GCM with a 192 bit key is a transform this responder never offers,
	// so the proposal parses and is then refused.
	unacceptable := Proposal{Number: 1, Protocol: ProtoIKE, Transforms: []Transform{
		{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 192},
		{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
		{Type: TransDH, ID: DH_CURVE25519},
	}}
	// drain clears anything an earlier attempt left in the queue, so a late
	// reply is never read as the answer to the next request.
	drain := func() {
		for {
			if _, err := mux.RecvIKEUntil(time.Now()); err != nil {
				return
			}
		}
	}
	// offer sends the request and answers a cookie challenge if one comes,
	// which it does above cookieThreshold and may do at any time, so whether
	// the responder demanded return routability is not what is under test. It
	// retries, because these are datagrams on a loopback socket shared with
	// every other test in this package and one of them can be dropped.
	offer := func(wait time.Duration, attempts int) (Notify, bool) {
		t.Helper()
		send := func(ahead []RawPayload) ([]byte, bool) {
			if err := mux.SendIKE(encodeTestSAInit(t, spiI, ni, unacceptable, ahead)); err != nil {
				t.Fatal(err)
			}
			reply, err := mux.RecvIKEUntil(time.Now().Add(wait))
			return reply, err == nil
		}
		for range attempts {
			drain()
			reply, ok := send(nil)
			if !ok {
				continue
			}
			answer := firstTestNotify(t, reply)
			if answer.Type != N_COOKIE {
				return answer, true
			}
			cookie := []RawPayload{{Type: PayloadN, Body: EncodeNotify(answer)}}
			if reply, ok := send(cookie); ok {
				return firstTestNotify(t, reply), true
			}
		}
		return Notify{}, false
	}

	// With the slots free the responder does answer, which is what makes the
	// silence below mean anything.
	answer, answered := offer(5*time.Second, 4)
	if !answered {
		t.Fatal("an unacceptable offer drew no answer at all")
	}
	if answer.Type != N_NO_PROPOSAL_CHOSEN {
		t.Fatalf("an unacceptable offer drew notify %d, want NO_PROPOSAL_CHOSEN", answer.Type)
	}

	for range halfOpenLimit {
		if !h.responder.enterHalfOpen() {
			t.Fatal("the responder refused a slot below its own limit")
		}
	}

	if answer, answered := offer(2*time.Second, 2); answered {
		t.Fatalf("with every half-open slot taken the responder still answered notify %d, so it parsed the offer before it checked whether it had room for one",
			answer.Type)
	}
}

// firstTestNotify reads the single notify out of a stateless answer.
func firstTestNotify(t *testing.T, raw []byte) Notify {
	t.Helper()
	message, err := DecodeMessage(raw)
	if err != nil {
		t.Fatalf("decode the response: %v", err)
	}
	payload := message.find(PayloadN)
	if payload == nil {
		t.Fatal("the response carried no notify")
	}
	notify, err := DecodeNotify(payload.Body)
	if err != nil {
		t.Fatalf("decode the notify: %v", err)
	}
	return notify
}

// buildTestSAInit produces a well-formed IKE_SA_INIT request, which is what
// RFC 7296 section 2.5: a payload this profile does not implement, marked
// critical, changes what the message means, so it has to be refused by type
// rather than skipped. The answer is stateless and costs nothing, which is the
// only reason it can be given before anything about the peer is known.
func TestResponderRefusesACriticalPayloadItDoesNotImplement(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })

	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// PayloadCERTREQ is a type this profile does not implement, and nothing
	// else about the request is wrong.
	critical := []RawPayload{{Type: PayloadCERTREQ, Critical: true, Body: []byte{0}}}
	if err := mux.SendIKE(encodeTestSAInit(t, spiI, ni, ikeProposal(), critical)); err != nil {
		t.Fatal(err)
	}
	reply, err := mux.RecvIKEUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("a critical payload we do not implement drew no answer: %v", err)
	}
	notify := firstTestNotify(t, reply)
	if notify.Type != N_UNSUPPORTED_CRITICAL_PAYLOAD {
		t.Fatalf("the responder answered notify %d, want UNSUPPORTED_CRITICAL_PAYLOAD", notify.Type)
	}
	if len(notify.Data) != 1 || PayloadType(notify.Data[0]) != PayloadCERTREQ {
		t.Errorf("the notify named %v, want the payload type that was refused", notify.Data)
	}
	select {
	case sess := <-h.sessions:
		sess.Mux().Close()
		t.Error("the responder carried the exchange forward anyway")
	default:
	}
}

// Our AUTH signs the IDr we send. Answering under a name we do not own would
// hand the initiator a signature over an identity of its choosing, made with
// this node's key, which is the whole of what authentication here rests on.
func TestResponderRefusesAnIdentityItDoesNotAnswerTo(t *testing.T) {
	h := newResponderHarness(t, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// Everything is as the working dial except the name asked for, which this
	// responder is not configured with.
	session, err := InitiateContext(ctx, PeerConfig{
		Organization:     "testorg",
		LocalCommonName:  "client",
		LocalSerial:      "2",
		LocalPrivateKey:  h.private,
		RemoteCommonName: "someone-else",
		RemoteSerial:     "1",
		RemotePublicKey:  h.public,
		RemoteAddr:       net.ParseIP("127.0.0.1"),
		RemotePort:       h.remotePort,
		Hub:              h.initiator,
	})
	if err == nil {
		session.Mux().Close()
		t.Fatal("the responder authenticated under a name it does not answer to")
	}
	select {
	case sess := <-h.sessions:
		sess.Mux().Close()
		t.Error("the responder produced a session for an identity it does not own")
	case <-time.After(time.Second):
	}
}

// buildTestSAInit produces a well-formed IKE_SA_INIT request, the shape
// the responder needs before it will park in awaitAuthRequest.
func buildTestSAInit(t *testing.T) ([]byte, uint64) {
	t.Helper()
	spiI := randUint64Nonzero()
	ni := make([]byte, 32)
	rand.Read(ni)
	return encodeTestSAInit(t, spiI, ni, ikeProposal(), nil), spiI
}

// encodeTestSAInit is buildTestSAInit with the parts a test may want to vary:
// the SPI and nonce a cookie is bound to, which proposal is offered, and what
// precedes the rest, which is where RFC 7296 section 2.6 puts an echoed
// cookie.
func encodeTestSAInit(t *testing.T, spiI uint64, ni []byte, proposal Proposal, ahead []RawPayload) []byte {
	t.Helper()
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	hashAlgos := make([]byte, 2)
	binary.BigEndian.PutUint16(hashAlgos, HashIdentity)
	payloads := slices.Concat(ahead, []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{proposal})},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
		{Type: PayloadNonce, Body: EncodeNonce(ni)},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_SIGNATURE_HASH_ALGORITHMS, Data: hashAlgos})},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_SOURCE_IP, Data: natDetectionHash(spiI, 0, net.IPv4(10, 0, 0, 1), 0)})},
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_NAT_DETECTION_DESTINATION_IP, Data: natDetectionHash(spiI, 0, net.ParseIP("127.0.0.1"), 0)})},
	})
	header := Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
	return (&Message{Header: header, Payloads: payloads}).Encode()
}

// A session that is resolved away the moment it is established is closed
// before anything ever serves it, so its Run loop never starts. Routing the
// Delete through that loop's request queue sends nothing at all, and the peer
// is left holding an SA it keeps transmitting into until its own dead peer
// detection expires.
func TestDeleteIKEReachesPeerWithoutRunLoop(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	<-h.identities

	// Deliberately no Run on either side, which is the state adopt closes a
	// session in.
	start := time.Now()
	if err := initiator.DeleteIKE(); err != nil {
		t.Fatalf("DeleteIKE: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("DeleteIKE took %s with nothing to wait for", elapsed)
	}

	raw, err := responder.Mux().RecvIKEUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatalf("the peer never received the Delete: %v", err)
	}
	header, err := decodeHeader(raw)
	if err != nil {
		t.Fatalf("decode what arrived: %v", err)
	}
	if header.ExchangeType != INFORMATIONAL {
		t.Errorf("the peer received exchange type %d, want INFORMATIONAL", header.ExchangeType)
	}
}

// A link that carries nothing but babel hellos and DPD has no ESP to refresh
// the liveness clock, so an answered exchange has to count as proof on its
// own. Without it Active()'s window silently becomes a function of
// babel.hello_interval, which nothing validates against it.
func TestAnsweredExchangeRefreshesLivenessClock(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	<-h.identities

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go func() { _ = initiator.Run(ctx) }()
	go func() { _ = responder.Run(ctx) }()

	// Run refreshes the clock once when it starts, so wait for that to settle
	// before taking the baseline. Nothing else touches it here: no ESP flows,
	// and the exchange below is the only thing on the wire.
	deadline := time.Now().Add(10 * time.Second)
	var before int64
	for stable := 0; stable < 20; {
		if time.Now().After(deadline) {
			t.Fatal("the responder's liveness clock never settled")
		}
		time.Sleep(5 * time.Millisecond)
		if now := responder.lastActive.Load(); now != before || !responder.serving.Load() {
			before, stable = now, 0
			continue
		}
		stable++
	}
	if before == 0 {
		t.Fatal("the responder's control loop never started")
	}

	if _, err := initiator.request(INFORMATIONAL, nil); err != nil {
		t.Fatalf("liveness exchange: %v", err)
	}
	answered := time.Now().Add(5 * time.Second)
	for responder.lastActive.Load() <= before {
		if time.Now().After(answered) {
			t.Fatal("an answered exchange left the responder's liveness clock untouched")
		}
	}
	if !responder.Active() {
		t.Error("the responder reads as dead after answering")
	}
}

// observedEndpoint returns the endpoint a hub reports for a datagram from one
// UDP socket. transport.Endpoint cannot be implemented outside its package, so
// a test that needs two distinct peer addresses has to observe two.
func observedEndpoint(t *testing.T, hub *transport.Hub, spi uint64) transport.Endpoint {
	t.Helper()
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterIKE(spi); err != nil {
		t.Fatal(err)
	}
	peer := listenPeer(t)
	request := make([]byte, 28)
	binary.BigEndian.PutUint64(request[:8], spi)
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	_, endpoint, err := mux.RecvIKEFromUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	return endpoint
}

// Under pressure a request without a currently valid cookie must be answered
// with one and dropped. RFC 7296 section 2.6 is the whole point of the
// mechanism: without it an off-path source can make the responder allocate for
// an address it never has to receive at.
func TestResponderDemandsCookieUnderPressure(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	endpoint := observedEndpoint(t, hub, 0x1111)

	r := &Responder{halfOpen: cookieThreshold}
	r.cfg.Hub = hub
	required, err := r.cookieRequired(&Message{}, bytes.Repeat([]byte{7}, 32), 1, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Fatal("a request under pressure was carried forward with no cookie at all")
	}

	// Below the threshold it does nothing at all, keeping the
	// ordinary case a two-message exchange.
	quiet := &Responder{}
	quiet.cfg.Hub = hub
	required, err = quiet.cookieRequired(&Message{}, bytes.Repeat([]byte{7}, 32), 1, endpoint)
	if err != nil {
		t.Fatal(err)
	}
	if required {
		t.Error("an idle responder demanded a cookie, which costs every handshake a round trip")
	}
}

func TestResponderRefusesCookieItDidNotIssue(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	endpoint := observedEndpoint(t, hub, 0x2222)
	elsewhere := observedEndpoint(t, hub, 0x3333)

	r := &Responder{halfOpen: cookieThreshold}
	r.cfg.Hub = hub
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		t.Fatal(err)
	}
	r.cookieRotated = time.Now()
	nonce := bytes.Repeat([]byte{7}, 32)
	valid := cookieValue(r.cookieSecret, r.cookieVersion, nonce, 1, endpoint)

	withCookie := func(data []byte) *Message {
		return &Message{Payloads: []RawPayload{
			{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: data})},
		}}
	}
	accepted := func(t *testing.T, request *Message, ni []byte, spi uint64, ep transport.Endpoint) bool {
		t.Helper()
		required, err := r.cookieRequired(request, ni, spi, ep)
		if err != nil {
			t.Fatal(err)
		}
		return !required
	}

	if !accepted(t, withCookie(valid), nonce, 1, endpoint) {
		t.Fatal("the responder refused a cookie it had just issued")
	}
	for name, forged := range map[string][]byte{
		"empty":            {},
		"version only":     valid[:1],
		"wrong version":    append([]byte{valid[0] + 1}, valid[1:]...),
		"flipped last bit": append(append([]byte{}, valid[:len(valid)-1]...), valid[len(valid)-1]^1),
		"right length":     bytes.Repeat([]byte{0}, len(valid)),
	} {
		t.Run(name, func(t *testing.T) {
			if accepted(t, withCookie(forged), nonce, 1, endpoint) {
				t.Error("the responder took a cookie it never issued, which is worse than issuing none")
			}
		})
	}

	// Bound to the attempt, so a cookie is useless for another nonce, another
	// SPI, or another address: that binding is what stops an off-path source
	// collecting one and spending it on addresses it cannot receive at.
	for name, replay := range map[string]func() bool{
		"another nonce":   func() bool { return accepted(t, withCookie(valid), bytes.Repeat([]byte{8}, 32), 1, endpoint) },
		"another SPI":     func() bool { return accepted(t, withCookie(valid), nonce, 2, endpoint) },
		"another address": func() bool { return accepted(t, withCookie(valid), nonce, 1, elsewhere) },
	} {
		t.Run(name, func(t *testing.T) {
			if replay() {
				t.Error("a cookie issued for one attempt was accepted for another")
			}
		})
	}
}

// halfOpenLimit caps what a flood can allocate even with valid cookies, which
// is the second half of RFC 7296 section 2.6: the cookie makes the source
// prove an address, the cap bounds what one proven address can hold.
func TestResponderCapsHalfOpenExchanges(t *testing.T) {
	r := &Responder{}
	for i := range halfOpenLimit {
		if !r.enterHalfOpen() {
			t.Fatalf("the responder refused half-open exchange %d, below its own limit", i)
		}
	}
	if r.enterHalfOpen() {
		t.Fatal("the responder allocated past its half-open limit, so a flood is bounded by nothing")
	}
	r.leaveHalfOpen()
	if !r.enterHalfOpen() {
		t.Error("a completed exchange did not free its slot")
	}
}

// RFC 7296 section 3.3.5 forbids the Key Length attribute on a fixed-key
// transform, and section 3.3.6 requires a selected transform to come back with
// the attributes it was offered with. ChaCha20-Poly1305 is offered without
// one, so the answer must carry none either. Getting this wrong is a silent
// interop break: charon and this fork's own initiator both reject the result,
// and AES-GCM being first in the proposal is why no handshake ever shows it.
func TestChaChaChildResponseEchoesNoKeyLength(t *testing.T) {
	child := responderChild{
		number:     1,
		encryption: Transform{Type: TransEncr, ID: ENCR_CHACHA20_POLY1305, KeyLengthBits: 256},
	}
	proposal := child.proposal(binary.BigEndian.AppendUint32(nil, 0x11223344))
	for _, transform := range proposal.Transforms {
		if transform.Type == TransEncr && transform.KeyLengthBits != 0 {
			t.Errorf("the IKE_AUTH response offered ChaCha20-Poly1305 with Key Length %d, which RFC 7296 section 3.3.5 forbids",
				transform.KeyLengthBits)
		}
	}

	// An attributed cipher keeps its key length, or the answer would be
	// proposing something different from what was selected.
	child.encryption = Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}
	proposal = child.proposal(binary.BigEndian.AppendUint32(nil, 0x11223344))
	for _, transform := range proposal.Transforms {
		if transform.Type == TransEncr && transform.KeyLengthBits != 128 {
			t.Errorf("AES-GCM came back with Key Length %d, want 128", transform.KeyLengthBits)
		}
	}
}
