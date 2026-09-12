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
	identities chan Identity
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
		identities: make(chan Identity, 1),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go responder.Serve(ctx, func(s *Session, id Identity) {
		h.sessions <- s
		h.identities <- id
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

	if id := <-h.identities; id != (Identity{Organization: "testorg", CommonName: "client", SerialNumber: "2"}) {
		t.Fatalf("authenticated identity = %s", id)
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

func TestIdentityRejectsNonCanonicalEncoding(t *testing.T) {
	id := Identity{Organization: "testorg", CommonName: "server", SerialNumber: "1"}
	body := id.encodeID()
	// The serial number is a PrintableString; the same characters as a
	// UTF8String name the same peer to a lenient parser and must not here,
	// or one AUTH signature would cover two distinct byte strings.
	swapped := bytes.Replace(body, []byte{0x13, 0x01, '1'}, []byte{0x0c, 0x01, '1'}, 1)
	if bytes.Equal(swapped, body) {
		t.Fatal("test did not alter the encoding")
	}
	if _, err := identityFromID(swapped); err == nil {
		t.Fatal("a re-tagged attribute was accepted")
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
		if accepted.CommonName != "client" {
			t.Fatalf("the responder accepted %q", accepted.CommonName)
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
