package ike

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
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
// answerBudget is how long a test waits for an answer it expects to arrive. It
// is generous because a loaded machine is not a failing implementation: an
// answer that never comes still fails, just later, while a budget tuned to an
// idle machine turns load into a false red. An assertion that expects silence
// uses a short wait instead, where the only cost of being wrong is a spurious
// pass rather than a spurious failure.
const answerBudget = 30 * time.Second

func newResponderHarness(t *testing.T, lookup func(Identity) (ed25519.PublicKey, bool)) *responderHarness {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	responderHub, err := transport.NewHub(":0", 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { responderHub.Close() })
	initiatorHub, err := transport.NewHub(":0", 0)
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
	return InitiateContext(ctx, h.peerConfig())
}

// Initiate is the blocking form, and the one the package documents its whole
// profile on. Only the cmd test binaries call it, so without this no test
// reaches it and it could stop compiling to the same thing.
func TestInitiateIsInitiateContextWithNoDeadline(t *testing.T) {
	h := newResponderHarness(t, nil)
	session, err := Initiate(h.peerConfig())
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer session.Mux().Close()
	responder := <-h.sessions
	defer responder.Mux().Close()
	if accepted := <-h.identities; accepted.Peer.CommonName != "client" {
		t.Fatalf("the responder accepted %q", accepted.Peer.CommonName)
	}
}

func (h *responderHarness) peerConfig() PeerConfig {
	return PeerConfig{
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
	}
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
	// RFC 7296 section 3.3.2's transform registry gives integrity algorithm 0
	// the name NONE, and an AEAD cipher needs none, so a peer that spells it
	// out alongside one says what omitting the transform says. strongSwan and
	// libreswan both write it out.
	t.Run("takes an offer that spells out INTEG NONE and echoes it", func(t *testing.T) {
		integ := Transform{Type: TransInteg, ID: INTEG_NONE}
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			integ,
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		selected, _, err := selectIKEProposal(body, DH_CURVE25519)
		if err != nil {
			t.Fatalf("an offer naming INTEG NONE was refused: %v", err)
		}
		// "The accepted cryptographic suite MUST contain exactly one transform
		// of each type included in the proposal", RFC 7296 section 2.7.
		if !slices.Contains(selected.Transforms, integ) {
			t.Errorf("the answer is %v, which drops a transform type the offer included", selected.Transforms)
		}
	})
	t.Run("rejects an integrity transform it cannot use", func(t *testing.T) {
		body := offer(
			Transform{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 256},
			Transform{Type: TransPRF, ID: PRF_HMAC_SHA2_256},
			Transform{Type: TransInteg, ID: 12},
			Transform{Type: TransDH, ID: DH_CURVE25519},
		)
		if _, _, err := selectIKEProposal(body, DH_CURVE25519); err == nil {
			t.Fatal("an integrity transform this implementation has no key for was accepted")
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
		t.Fatalf("local request was not picked up within 2s, dpd interval is %s", defaultDPDInterval)
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
	first, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
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
	again, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("an identical retransmission was not answered: %v", err)
	}
	if !bytes.Equal(first, again) {
		t.Error("the retransmission drew a different response than the original")
	}
}

// The slot has to come before the key exchange rather than after it, for the
// reason enterHalfOpen's call site gives.
//
// The observable is the last stateless answer before the key exchange: an
// offer this responder cannot accept draws NO_PROPOSAL_CHOSEN, so receiving
// one proves execution reached selectIKEProposal. With every slot taken that
// answer must not come, because the refusal happens first.
func TestResponderTakesSlotBeforeKeyExchange(t *testing.T) {
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

	// With the slots free the responder does answer, which gives the silence
	// below its meaning.
	answer, answered := offer(answerBudget, 4)
	if !answered {
		t.Fatal("an unacceptable offer drew no answer at all")
	}
	if answer.Type != N_NO_PROPOSAL_CHOSEN {
		t.Fatalf("an unacceptable offer drew notify %d, want NO_PROPOSAL_CHOSEN", answer.Type)
	}

	// Filled from enough distinct addresses that the global cap runs out
	// rather than any one source's share.
	for i := range halfOpenLimit {
		if !h.responder.enterHalfOpen(netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i/halfOpenPerSource))) {
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

// RFC 7296 section 2.5: a payload this profile does not implement, marked
// critical, changes what the message means, so it has to be refused by type
// rather than skipped. The answer is stateless and costs nothing, which is the
// only reason it can be given before anything about the peer is known.
func TestResponderRefusesCriticalPayloadItDoesNotImplement(t *testing.T) {
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
	reply, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
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
func TestResponderRefusesIdentityItDoesNotAnswerTo(t *testing.T) {
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
	// session in. DeleteIKE has to notice that and send directly, because
	// routing the Delete through the run loop's request queue blocks forever, so
	// the deadline is its own goroutine rather than an elapsed-time check that
	// is only reached if the call returns at all.
	deleted := make(chan error, 1)
	go func() { deleted <- initiator.DeleteIKE() }()
	select {
	case err := <-deleted:
		if err != nil {
			t.Fatalf("DeleteIKE: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("DeleteIKE never returned, so it is waiting on a run loop that does not exist")
	}

	raw, err := responder.Mux().RecvIKEUntil(time.Now().Add(answerBudget))
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
	_, endpoint, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
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
	hub, err := transport.NewHub("127.0.0.1:0", 0)
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
	hub, err := transport.NewHub("127.0.0.1:0", 0)
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
	// SPI, or another address: that binding stops an off-path source
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
	source := func(i int) netip.Addr { return netip.MustParseAddr(fmt.Sprintf("198.51.100.%d", i/halfOpenPerSource)) }
	for i := range halfOpenLimit {
		if !r.enterHalfOpen(source(i)) {
			t.Fatalf("the responder refused half-open exchange %d, below its own limit", i)
		}
	}
	if r.enterHalfOpen(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("the responder allocated past its half-open limit, so a flood is bounded by nothing")
	}
	r.leaveHalfOpen(source(0))
	if !r.enterHalfOpen(source(0)) {
		t.Error("a completed exchange did not free its slot")
	}
}

// The cap is also per address, or it is first come from one: an initiator that
// sends IKE_SA_INIT and never IKE_AUTH holds a slot for the whole handshake
// timeout, so one address parks all of them and every legitimate peer is then
// refused after answering its cookie correctly.
func TestOneAddressCannotHoldEveryHalfOpenSlot(t *testing.T) {
	r := &Responder{}
	flood := netip.MustParseAddr("198.51.100.1")
	for i := range halfOpenPerSource {
		if !r.enterHalfOpen(flood) {
			t.Fatalf("one address was refused its %dth exchange, below its own share", i)
		}
	}
	if r.enterHalfOpen(flood) {
		t.Error("one address took more than its share, so it can park every slot")
	}
	if !r.enterHalfOpen(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("a peer at another address was refused while the node was nowhere near its limit")
	}
	// And the share is given back, or an address that once flooded is locked
	// out for the life of the process.
	for range halfOpenPerSource {
		r.leaveHalfOpen(flood)
	}
	if !r.enterHalfOpen(flood) {
		t.Error("an address that finished its exchanges never got its share back")
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.halfOpenBySource) != 2 {
		t.Errorf("the responder is tracking %d addresses, want only the two still holding slots", len(r.halfOpenBySource))
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

// A session that has just been established has to read as live before it has
// carried anything. A peer that reboots leaves an SA here that looks
// established for a full dead-peer-detection window, and the rule that sorts
// that out asks whether a session has recently proved the peer is there. A
// handshake that just completed is exactly that proof. Without it a fresh
// session reads as dead, the path is reported unheld, and the dialer opens
// another SA over a perfectly good one on every reconnect delay.
func TestFreshlyEstablishedSessionReadsAsLive(t *testing.T) {
	h := newResponderHarness(t, nil)
	initiator, err := h.dial(t)
	if err != nil {
		t.Fatalf("initiate: %v", err)
	}
	defer initiator.Mux().Close()
	if !initiator.Active() {
		t.Error("the dialer's own session reads as dead the moment it is established")
	}
	var responder *Session
	select {
	case responder = <-h.sessions:
	case <-time.After(10 * time.Second):
		t.Fatal("the responder produced no session")
	}
	defer responder.Mux().Close()
	if !responder.Active() {
		t.Error("the answering side of the same handshake reads as dead")
	}
}

// Dead peer detection asks a peer that has gone quiet whether it is still
// there. A peer sending continuously is not quiet, and ESP is the only thing
// that says so on a link carrying nothing but data: without the loop consuming
// that edge, a busy session is probed every ten seconds forever, and each
// probe is a round trip the peer has to answer while it is already saturating
// the link.
func TestTrafficPostponesDeadPeerDetection(t *testing.T) {
	probed := func(t *testing.T, traffic bool) bool {
		t.Helper()
		h := newResponderHarness(t, nil)
		initiator, err := h.dial(t)
		if err != nil {
			t.Fatalf("initiate: %v", err)
		}
		t.Cleanup(func() { initiator.Mux().Close() })
		var peer *Session
		select {
		case peer = <-h.sessions:
		case <-time.After(10 * time.Second):
			t.Fatal("the responder produced no session")
		}
		t.Cleanup(func() { peer.Mux().Close() })

		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		go func() { _ = initiator.Run(ctx) }()
		if traffic {
			go func() {
				for ctx.Err() == nil {
					initiator.NoteTraffic()
					time.Sleep(200 * time.Millisecond)
				}
			}()
		}
		// Nothing runs the responder's own loop, so whatever arrives here is
		// what the initiator sent unprompted.
		_, err = peer.Mux().RecvIKEUntil(time.Now().Add(defaultDPDInterval + 3*time.Second))
		return err == nil
	}
	// The quiet session is the positive control: without it, a busy session
	// that is never probed proves nothing about why.
	t.Run("a quiet session", func(t *testing.T) {
		t.Parallel()
		if !probed(t, false) {
			t.Error("a session that carried nothing was never probed, so dead peer detection is not running at all")
		}
	})
	t.Run("a session carrying traffic", func(t *testing.T) {
		t.Parallel()
		if probed(t, true) {
			t.Error("a session carrying traffic was probed anyway, so the traffic edge reaches nothing")
		}
	})
}

// The share is per address, not per flow. Keyed by the whole endpoint it
// bounds one UDP flow instead, and a second source port from the same address
// takes another sixteen slots, which is the partition the share exists to
// prevent: sixteen ports from one address hold all 256.
func TestHalfOpenShareIsPerAddressNotPerFlow(t *testing.T) {
	h := newResponderHarness(t, nil)
	loopback := netip.MustParseAddr("127.0.0.1")
	// Everything one address is allowed, spent before either dial.
	for range halfOpenPerSource {
		if !h.responder.enterHalfOpen(loopback) {
			t.Fatal("the responder refused a slot below one address's share")
		}
	}

	dial := func(hub *transport.Hub) error {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		cfg := h.peerConfig()
		cfg.Hub = hub
		session, err := InitiateContext(ctx, cfg)
		if err == nil {
			session.Mux().Close()
		}
		return err
	}
	if err := dial(h.initiator); err == nil {
		t.Error("a dial from an address that had spent its share was answered")
	}
	// A second hub on the same machine is the same address and a different
	// source port, which is all an attacker has to vary.
	other, err := transport.NewHub("127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if err := dial(other); err == nil {
		t.Error("a second source port from the same address took another share, so sixteen ports hold every slot")
	}
	h.responder.mu.Lock()
	defer h.responder.mu.Unlock()
	if got := len(h.responder.halfOpenBySource); got != 1 {
		t.Errorf("the responder is tracking %d sources for one address", got)
	}
}

// An initiator that does not advertise the Ed25519 Identity hash is offering
// an authentication method this responder cannot use, which RFC 7296 section
// 3.10.1 calls NO_PROPOSAL_CHOSEN: "any case where the offered proposals
// (including but not limited to SA payload values, USE_TRANSPORT_MODE notify,
// IPCOMP_SUPPORTED notify) are not acceptable for the responder".
// AUTHENTICATION_FAILED is defined there as
// the answer to an IKE_AUTH message, and this exchange has not reached one.
func TestResponderRefusesOfferItCannotAuthenticate(t *testing.T) {
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
	// Everything a working IKE_SA_INIT carries except the signature hash
	// notify, which declares that this initiator can verify an Ed25519 AUTH.
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	request := (&Message{
		Header: Header{SPIInitiator: spiI, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator},
		Payloads: []RawPayload{
			{Type: PayloadSA, Body: EncodeSA([]Proposal{ikeProposal()})},
			{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
			{Type: PayloadNonce, Body: EncodeNonce(ni)},
		},
	}).Encode()
	if err := mux.SendIKE(request); err != nil {
		t.Fatal(err)
	}
	reply, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatalf("an offer this responder cannot authenticate drew no answer: %v", err)
	}
	if got := firstTestNotify(t, reply).Type; got != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("the responder answered notify %d, want NO_PROPOSAL_CHOSEN", got)
	}
}

// A spoofer must not be able to spend a named peer's share while the node is
// idle. With the cookie demanded on the global count alone, an off-path source
// forging a victim's address takes the victim's whole share below the
// threshold, at sixteen packets every thirty seconds, and the victim is then
// refused in silence for as long as the attacker keeps it up.
func TestOneAddressCannotSpendItsShareWithoutCookie(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	r := &Responder{}
	r.cfg.Hub = hub
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		t.Fatal(err)
	}
	r.cookieRotated = time.Now()

	victim := observedEndpoint(t, hub, randUint64Nonzero())
	source := victim.AddrPort().Addr()
	nonce := bytes.Repeat([]byte{7}, 32)
	empty := &Message{}
	// The node is idle, so the global threshold is nowhere near.
	for i := range halfOpenPerSourceWithoutCookie {
		required, err := r.cookieRequired(empty, nonce, uint64(i+1), victim)
		if err != nil {
			t.Fatal(err)
		}
		if required {
			t.Fatalf("an idle responder demanded a cookie for slot %d, which costs every handshake a round trip", i)
		}
		if !r.enterHalfOpen(source) {
			t.Fatal("the responder refused a slot below one address's share")
		}
	}
	required, err := r.cookieRequired(empty, nonce, 99, victim)
	if err != nil {
		t.Fatal(err)
	}
	if !required {
		t.Error("one address took more of its share without proving it can receive, so a spoofer can spend a named peer's")
	}
	if r.halfOpen >= cookieThreshold {
		t.Fatalf("the global threshold was reached at %d, so this proves nothing about the per-address one", r.halfOpen)
	}
}

// A cookie is issued and echoed a round trip apart. Rotating the secret in
// between refused every cookie in flight, and RFC 7296 section 2.6's retry
// carries the one cookie the initiator was given, so the exchange then failed
// on a cookie that could never be accepted. The per-address pressure term
// makes "under pressure" the ordinary state for any address holding two
// half-open exchanges, so the rotation is no longer a load condition.
func TestCookieSurvivesRotationThatFollowsIt(t *testing.T) {
	hub, err := transport.NewHub("127.0.0.1:0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	r := &Responder{}
	r.cfg.Hub = hub
	if _, err := rand.Read(r.cookieSecret[:]); err != nil {
		t.Fatal(err)
	}
	endpoint := observedEndpoint(t, hub, randUint64Nonzero())
	nonce := bytes.Repeat([]byte{7}, 32)
	// Enough half-open exchanges from this address that a cookie is demanded.
	r.halfOpenBySource = map[netip.Addr]int{endpoint.AddrPort().Addr(): halfOpenPerSourceWithoutCookie}
	r.cookieRotated = time.Now()

	issued := cookieValue(r.cookieSecret, r.cookieVersion, nonce, 1, endpoint)
	echoed := &Message{Payloads: []RawPayload{
		{Type: PayloadN, Body: EncodeNotify(Notify{Type: N_COOKIE, Data: issued})},
	}}
	if required, err := r.cookieRequired(echoed, nonce, 1, endpoint); err != nil || required {
		t.Fatalf("the responder refused the cookie it had just issued: required=%v err=%v", required, err)
	}

	// The secret rotates while the retry is still on the wire.
	r.cookieRotated = time.Now().Add(-2 * cookieLifetime)
	if required, err := r.cookieRequired(echoed, nonce, 1, endpoint); err != nil || required {
		t.Errorf("a cookie in flight through a rotation was refused: required=%v err=%v", required, err)
	}
	if !r.previousValid {
		t.Fatal("no rotation happened, so this proves nothing")
	}

	// One generation is all that is kept: a cookie two rotations old is older
	// than the lifetime it was issued under.
	r.cookieRotated = time.Now().Add(-2 * cookieLifetime)
	if required, err := r.cookieRequired(echoed, nonce, 1, endpoint); err != nil || !required {
		t.Errorf("a cookie two rotations old was still accepted: required=%v err=%v", required, err)
	}
}

// RFC 7296 section 2.21.2 leaves the IKE SA created when only the Child SA
// bundled into IKE_AUTH fails, and says the initiator "MAY, of course, for
// reasons of policy later delete such an IKE SA". This fork's policy is to
// delete it, and this responder closes its mux with that response, so the
// Delete is never answered. Retransmitting it to the end of the ordinary
// budget delayed the dial's failure by sixty-two seconds for a result the
// response had already named.
func TestTearingDownUnusableIKESADoesNotSpendTheWholeBudget(t *testing.T) {
	if teardownRetransmits >= maxRetransmits {
		t.Fatalf("the teardown budget is %d of %d attempts, so nothing is bounded", teardownRetransmits, maxRetransmits)
	}
	var budget time.Duration
	for attempt := range teardownRetransmits {
		budget += retransmitDelay(attempt + 1)
	}
	var full time.Duration
	for attempt := range maxRetransmits {
		full += retransmitDelay(attempt + 1)
	}
	// runPeer redials every ten seconds, so a teardown that outlasts that
	// delays the next attempt rather than the failed one.
	if budget > 10*time.Second {
		t.Errorf("a Delete nobody answers costs %s, out of the %s an exchange that matters gets", budget, full)
	}
}

// RFC 7296 section 2.10 is two rules, and the second needs the PRF: a nonce
// "MUST be at least 128 bits in size, and MUST be at least half the key size
// of the negotiated pseudorandom function". IKE_SA_INIT is the one exchange
// where the nonce arrives before the PRF is chosen, and it is the surface an
// unauthenticated peer reaches first, so checking only the length there left
// it as the one place a short nonce was taken.
func TestResponderChecksTheNonceAgainstTheNegotiatedPRF(t *testing.T) {
	h := newResponderHarness(t, nil)
	mux, err := h.initiator.NewMux(net.ParseIP("127.0.0.1"), h.remotePort)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { mux.Close() })
	spiI := randUint64Nonzero()
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	// Sixteen bytes: past the flat 128 bit floor, half the key size of
	// HMAC-SHA2-256 and a third of HMAC-SHA2-384's.
	short := bytes.Repeat([]byte{3}, 16)
	withPRF := func(prf uint16) Proposal {
		p := ikeProposal()
		p.Transforms = slices.Clone(p.Transforms)
		p.Transforms = slices.DeleteFunc(p.Transforms, func(t Transform) bool { return t.Type == TransPRF })
		return Proposal{Number: p.Number, Protocol: p.Protocol,
			Transforms: append(p.Transforms, Transform{Type: TransPRF, ID: prf})}
	}
	// offer retries, because these are datagrams on a loopback socket shared
	// with every other test in this package, and answers a cookie challenge if
	// one comes: whether return routability was demanded is not under test.
	offer := func(t *testing.T, proposal Proposal) Notify {
		t.Helper()
		for range 4 {
			for {
				if _, err := mux.RecvIKEUntil(time.Now()); err != nil {
					break
				}
			}
			send := func(ahead []RawPayload) (Notify, bool) {
				if err := mux.SendIKE(encodeTestSAInit(t, spiI, short, proposal, ahead)); err != nil {
					t.Fatal(err)
				}
				reply, err := mux.RecvIKEUntil(time.Now().Add(answerBudget))
				if err != nil {
					return Notify{}, false
				}
				return firstTestNotify(t, reply), true
			}
			answer, ok := send(nil)
			if !ok {
				continue
			}
			if answer.Type != N_COOKIE {
				return answer
			}
			if answer, ok := send([]RawPayload{{Type: PayloadN, Body: EncodeNotify(answer)}}); ok {
				return answer
			}
		}
		t.Fatal("the responder never answered")
		return Notify{}
	}

	if got := offer(t, withPRF(PRF_HMAC_SHA2_384)).Type; got != N_NO_PROPOSAL_CHOSEN {
		t.Errorf("a 16 byte nonce under HMAC-SHA2-384 drew notify %d, want NO_PROPOSAL_CHOSEN", got)
	}
	// The same nonce is long enough for the other PRF this responder offers,
	// so what the first case proves is the PRF rule and not the flat floor.
	if got := offer(t, withPRF(PRF_HMAC_SHA2_256)).Type; got == N_NO_PROPOSAL_CHOSEN {
		t.Error("a 16 byte nonce under HMAC-SHA2-256 was refused, which is the length rule rather than the PRF one")
	}
}

// Anyone who can see the responder SPI can send a datagram carrying the right
// IKE_AUTH header and contents this end cannot decrypt. Acting on one would
// end a handshake this end has already paid a key exchange for, which is the
// cheapest way to stop every session a node opens. Nothing unauthenticated
// changes state (RFC 7296 section 2.21, RFC 7815 section 2.1); the deadline is
// what ends the wait.
func TestUndecryptableDatagramDoesNotEndTheHandshake(t *testing.T) {
	hub, err := transport.NewHub(":0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	peerHub, err := transport.NewHub(":0", 0)
	if err != nil {
		t.Fatal(err)
	}
	defer peerHub.Close()
	port := func(h *transport.Hub) int { return h.LocalAddr().(*net.UDPAddr).Port }
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), port(peerHub))
	if err != nil {
		t.Fatal(err)
	}
	peer, err := peerHub.NewMux(net.IPv4(127, 0, 0, 1), port(hub))
	if err != nil {
		t.Fatal(err)
	}

	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	key := bytes.Repeat([]byte{9}, 20)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, skei: key, sker: key, responder: true}
	s := &Session{mux: mux, current: ctx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	header := Header{SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: IKE_AUTH,
		Flags: FlagInitiator, MessageID: 1}
	good, err := EncryptMessage(suite, key, header, nil, []RawPayload{{Type: PayloadN,
		Body: EncodeNotify(Notify{Type: N_INITIAL_CONTACT})}})
	if err != nil {
		t.Fatal(err)
	}
	// The same header, with the ciphertext replaced. It decodes and fails the
	// AEAD, which is the arm under test.
	bad := append([]byte(nil), good...)
	for i := len(bad) - 16; i < len(bad); i++ {
		bad[i] ^= 0xff
	}
	if err := peer.SendIKE(bad); err != nil {
		t.Fatal(err)
	}
	if err := peer.SendIKE(good); err != nil {
		t.Fatal(err)
	}

	got, err := s.awaitAuthRequest(nil, nil, time.Now().Add(10*time.Second))
	if err != nil {
		t.Fatalf("an undecryptable datagram ended the handshake: %v", err)
	}
	if !bytes.Equal(got.raw, good) {
		t.Error("the request returned is not the one that authenticated")
	}
}

// Anyone who can reach the port can make a handshake fail, so the line has to
// be rare; but at debug it was invisible at the default level, and an operator
// looking at "that peer cannot connect" had nothing on this side to read. Both
// halves matter: the first failure in an interval is said at warn, and the
// ones behind it drop to debug rather than being repeated.
func TestFailedInboundHandshakeIsSaidOnceAtWarn(t *testing.T) {
	var levels []slog.Level
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(&levelRecorder{levels: &levels}))

	r := &Responder{started: time.Now()}
	// What NewResponder does: primed one interval in the past so the first
	// failure is not swallowed by the limiter that exists for the repeats.
	r.failureReported.Store(-int64(handshakeFailureInterval))
	for range 4 {
		r.noteHandshakeFailure(nil, errors.New("no registry entry"))
	}
	if len(levels) != 4 {
		t.Fatalf("four failures wrote %d lines", len(levels))
	}
	if levels[0] != slog.LevelWarn {
		t.Errorf("the first failure in an interval is at %v, want warn: at debug an operator sees nothing", levels[0])
	}
	for _, level := range levels[1:] {
		if level != slog.LevelDebug {
			t.Errorf("a repeat inside the interval is at %v, want debug: anyone who can reach the port can drive these", level)
		}
	}
}

// levelRecorder keeps the level of every record and discards the rest.
type levelRecorder struct{ levels *[]slog.Level }

func (h *levelRecorder) Enabled(context.Context, slog.Level) bool { return true }
func (h *levelRecorder) Handle(_ context.Context, r slog.Record) error {
	*h.levels = append(*h.levels, r.Level)
	return nil
}
func (h *levelRecorder) WithAttrs([]slog.Attr) slog.Handler { return h }
func (h *levelRecorder) WithGroup(string) slog.Handler      { return h }
