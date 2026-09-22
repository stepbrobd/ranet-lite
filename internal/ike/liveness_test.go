package ike

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/transport"
)

func TestSessionRunStopsOnContextCancellation(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Session.Run did not stop after context cancellation")
	}
}

func TestRequestReturnsWhenTransportCloses(t *testing.T) {
	for _, waitingForResponse := range []bool{false, true} {
		t.Run(fmt.Sprint(waitingForResponse), func(t *testing.T) {
			mux, _ := lifecycleMuxes(t)
			s := &Session{mux: mux, current: &ikeContext{}, requests: make(chan *localRequest)}
			done := make(chan error, 1)
			go func() {
				_, err := s.request(CREATE_CHILD_SA, nil)
				done <- err
			}()
			if waitingForResponse {
				<-s.requests
			}
			mux.Close()
			select {
			case err := <-done:
				if err == nil {
					t.Fatal("request succeeded after transport closed")
				}
			case <-time.After(time.Second):
				t.Fatal("request remained blocked after transport closed")
			}
		})
	}
}

func TestNextDueRekeyPreservesChildPriority(t *testing.T) {
	child := &rekeySchedule{name: "Child SA", due: true}
	ike := &rekeySchedule{name: "IKE SA", due: true}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != child {
		t.Fatalf("first due schedule = %v, want Child SA", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, child); got != nil {
		t.Fatalf("selected %v while another rekey was running", got)
	}
	if got := nextDueRekey([]*rekeySchedule{child, ike}, nil); got != ike {
		t.Fatalf("second due schedule = %v, want IKE SA", got)
	}
}

func TestSupportedPayloadTypeRejectsUnknownCriticalType(t *testing.T) {
	if supportedPayloadType(PayloadType(250)) {
		t.Fatal("unknown payload type reported as supported")
	}
	if !supportedPayloadType(PayloadSA) {
		t.Fatal("SA payload type reported as unsupported")
	}
}

func TestRekeyRetryDelay(t *testing.T) {
	s := &Session{
		rekeyRetryInitial: 5 * time.Second,
		rekeyRetryMax:     time.Minute,
		rekeyJitterSource: func(time.Duration) (time.Duration, error) { return 0, nil },
	}
	for _, test := range []struct {
		failures uint
		want     time.Duration
	}{
		{1, 5 * time.Second},
		{2, 10 * time.Second},
		{3, 20 * time.Second},
		{4, 40 * time.Second},
		{5, time.Minute},
		{6, time.Minute},
	} {
		if got := s.rekeyRetryDelay(test.failures); got != test.want {
			t.Errorf("retry delay after %d failures = %s, want %s", test.failures, got, test.want)
		}
	}
}

// Two ends of a simultaneous rekey fail at the same instant and reset the same
// backoff, so an unjittered retry collides again on every attempt.
func TestRekeyRetryDelayIsSpreadOverUpperHalfOfWindow(t *testing.T) {
	s := &Session{rekeyRetryInitial: 5 * time.Second, rekeyRetryMax: time.Minute}
	seen := make(map[time.Duration]bool)
	for range 64 {
		got := s.rekeyRetryDelay(3)
		if got < 10*time.Second || got > 20*time.Second {
			t.Fatalf("retry delay = %s, want it within 10s..20s", got)
		}
		seen[got] = true
	}
	if len(seen) < 32 {
		t.Fatalf("64 draws produced %d distinct delays, want a spread", len(seen))
	}
}

func TestRequestRetransmitDelayIsExponential(t *testing.T) {
	want := []time.Duration{2 * time.Second, 4 * time.Second, 8 * time.Second, 16 * time.Second, 32 * time.Second}
	for i, delay := range want {
		if got := retransmitDelay(i + 1); got != delay {
			t.Fatalf("attempt %d delay = %v, want %v", i+1, got, delay)
		}
	}
}

func TestPostHandshakeRetransmitsRequireLivePeerToContinue(t *testing.T) {
	ordinary := &pendingRequest{attempts: maxRetransmits}
	if pendingRetransmitsExhausted(ordinary, true) {
		t.Fatal("ordinary request exhausted retransmissions while receiving authenticated traffic")
	}
	if !pendingRetransmitsExhausted(ordinary, false) {
		t.Fatal("unanswered rekey kept a silent peer alive indefinitely")
	}
	dpd := &pendingRequest{attempts: maxRetransmits, localRequest: localRequest{dpd: true}}
	if !pendingRetransmitsExhausted(dpd, true) {
		t.Fatal("DPD request did not exhaust retransmissions")
	}
}

func TestNoteTrafficCoalescesPacketsUntilRunConsumesThem(t *testing.T) {
	var s Session
	for range 1000 {
		s.NoteTraffic()
	}
	if !s.trafficSeen.Swap(false) {
		t.Fatal("authenticated traffic was not recorded")
	}
	if s.trafficSeen.Swap(false) {
		t.Fatal("traffic indication was not consumed")
	}
	s.NoteTraffic()
	if !s.trafficSeen.Swap(false) {
		t.Fatal("traffic after consumption was not recorded")
	}
}

func TestStartRequestConsumesMessageIDOnlyAfterSuccessfulSend(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	ctx := &ikeContext{
		suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		skei:  make([]byte, 20), spiI: 1, spiR: 2, nextLocalMID: 7,
	}
	s := &Session{mux: mux, current: ctx}
	if _, err := s.startRequest(&localRequest{exchange: INFORMATIONAL}); err != nil {
		t.Fatal(err)
	}
	if ctx.nextLocalMID != 8 {
		t.Fatalf("Message ID after successful send = %d, want 8", ctx.nextLocalMID)
	}

	failedMux, err := transport.Dial(":0", net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	if err := failedMux.Close(); err != nil {
		t.Fatal(err)
	}
	failedCtx := &ikeContext{
		suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128},
		skei:  make([]byte, 20), spiI: 3, spiR: 4, nextLocalMID: 11,
	}
	failed := &Session{mux: failedMux, current: failedCtx}
	if _, err := failed.startRequest(&localRequest{exchange: INFORMATIONAL}); err == nil {
		t.Fatal("startRequest succeeded with a closed transport")
	}
	if failedCtx.nextLocalMID != 11 {
		t.Fatalf("Message ID after failed send = %d, want 11", failedCtx.nextLocalMID)
	}
}

func TestMessageIDExhaustionCannotWrap(t *testing.T) {
	t.Run("local request", func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		ctx := &ikeContext{nextLocalMID: maxMessageID}
		s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest, 1)}
		runDone := make(chan error, 1)
		go func() { runDone <- s.Run(context.Background()) }()
		if _, err := s.request(INFORMATIONAL, nil); !errors.Is(err, errMessageIDExhausted) {
			t.Fatalf("request error = %v", err)
		}
		if ctx.nextLocalMID != maxMessageID {
			t.Fatalf("local Message ID wrapped to %d", ctx.nextLocalMID)
		}
		if err := <-runDone; !errors.Is(err, errMessageIDExhausted) {
			t.Fatalf("Run error = %v", err)
		}
		if !mux.IsClosed() {
			t.Fatal("IKE SA remained open at local Message ID exhaustion")
		}
	})

	t.Run("peer request", func(t *testing.T) {
		mux, _ := lifecycleMuxes(t)
		suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128}
		ctx := &ikeContext{
			suite: suite, spiI: 1, spiR: 2, sker: make([]byte, 20),
			nextPeerMID: maxMessageID,
		}
		s := &Session{mux: mux, current: ctx}
		request, err := EncryptMessage(suite, ctx.sker, Header{
			SPIInitiator: 1, SPIResponder: 2, ExchangeType: INFORMATIONAL,
			MessageID: maxMessageID,
		}, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		if !s.dispatch(request, nil, &pending) {
			t.Fatal("exhausting peer request was not authenticated")
		}
		if ctx.nextPeerMID != maxMessageID {
			t.Fatalf("peer Message ID wrapped to %d", ctx.nextPeerMID)
		}
		if !mux.IsClosed() {
			t.Fatal("IKE SA remained open at peer Message ID exhaustion")
		}
	})
}

func TestReplayedRequestDoesNotRefreshOrAdoptEndpoint(t *testing.T) {
	configured := listenPeer(t)
	rebound := listenPeer(t)
	configuredAddr := configured.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", configuredAddr.IP, configuredAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  spiI,
		spiR:  spiR,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	readIKE := func(peer *net.UDPConn) []byte {
		t.Helper()
		buf := make([]byte, 2048)
		if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
			t.Fatal(err)
		}
		n, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatal(err)
		}
		return append([]byte(nil), buf[4:n]...)
	}
	dispatchFrom := func(peer *net.UDPConn, request []byte) bool {
		t.Helper()
		if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
			t.Fatal(err)
		}
		raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
		if err != nil {
			t.Fatal(err)
		}
		var pending *pendingRequest
		return s.dispatch(raw, source, &pending)
	}

	request, err := EncryptMessage(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    0,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatchFrom(configured, request) {
		t.Fatal("fresh request was not reported as peer activity")
	}
	response := readIKE(configured)

	if dispatchFrom(rebound, request) {
		t.Fatal("replayed request was reported as fresh peer activity")
	}
	if replayResponse := readIKE(rebound); !bytes.Equal(replayResponse, response) {
		t.Fatal("replayed request did not receive the cached response")
	}
	if err := mux.SendIKE([]byte("probe")); err != nil {
		t.Fatal(err)
	}
	if got := readIKE(configured); string(got) != "probe" {
		t.Fatalf("packet after replay = %q, want configured endpoint", got)
	}

	freshRequest, err := EncryptMessage(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    1,
	}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !dispatchFrom(rebound, freshRequest) {
		t.Fatal("fresh request from rebound endpoint was not reported as peer activity")
	}
	_ = readIKE(rebound)
	if err := mux.SendIKE([]byte("future")); err != nil {
		t.Fatal(err)
	}
	if got := readIKE(rebound); string(got) != "future" {
		t.Fatalf("packet after fresh request = %q, want rebound endpoint", got)
	}
}

func TestAuthenticatedMalformedRequestGetsInvalidSyntax(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI = 0x0102030405060708
	const spiR = 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  spiI,
		spiR:  spiR,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	// The authenticated plaintext contains a generic payload whose declared
	// length is shorter than its four-byte header, followed by zero padding.
	request, err := encryptMessagePlaintextIV(suite, ikeCtx.sker, Header{
		SPIInitiator: spiI,
		SPIResponder: spiR,
		ExchangeType: INFORMATIONAL,
		MessageID:    0,
	}, nil, PayloadN, []byte{0, 0, 0, 3, 0}, make([]byte, 8))
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(answerBudget))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("authenticated malformed request was not handled")
	}

	buf := make([]byte, 2048)
	if err := peer.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatal(err)
	}
	responseRaw := buf[4:n]
	response, err := DecodeMessage(responseRaw)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, responseRaw, response)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadN {
		t.Fatalf("response payloads = %#v, want INVALID_SYNTAX", inner)
	}
	notify, err := DecodeNotify(inner[0].Body)
	if err != nil || notify.Type != N_INVALID_SYNTAX {
		t.Fatalf("response notify = %#v, %v", notify, err)
	}
	if !mux.IsClosed() {
		t.Fatal("IKE SA remained open after fatal INVALID_SYNTAX")
	}
}

func TestChildRequestRejectionNotifications(t *testing.T) {
	const unknownSPI = 0x10203040
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{current: ikeCtx, Child: ChildSA{RemoteSPI: 0x50607080}}
	newSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(newSPI, 0x90a0b0c0)
	base := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: newSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}

	decodeResponse := func(raw []byte) Notify {
		t.Helper()
		message, err := DecodeMessage(raw)
		if err != nil {
			t.Fatal(err)
		}
		inner, err := DecryptMessage(suite, ikeCtx.skei, raw, message)
		if err != nil {
			t.Fatal(err)
		}
		if len(inner) != 1 || inner[0].Type != PayloadN {
			t.Fatalf("response payloads = %#v, want one Notify", inner)
		}
		notify, err := DecodeNotify(inner[0].Body)
		if err != nil {
			t.Fatal(err)
		}
		return notify
	}

	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	additionalRequest := append([]RawPayload(nil), base[:2]...)
	additionalRequest = append(additionalRequest, RawPayload{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())})
	additionalRequest = append(additionalRequest, base[2:]...)
	response, err := s.handleChildRekey(ikeCtx, 1, additionalRequest)
	if err != nil {
		t.Fatal(err)
	}
	additional := decodeResponse(response)
	if additional.Type != N_NO_ADDITIONAL_SAS || additional.Protocol != 0 || len(additional.SPI) != 0 {
		t.Fatalf("additional Child SA rejection = %#v", additional)
	}

	unknown := make([]byte, 4)
	binary.BigEndian.PutUint32(unknown, unknownSPI)
	rekey := append([]RawPayload{{Type: PayloadN, Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: unknown, Type: N_REKEY_SA})}}, base...)
	response, err = s.handleChildRekey(ikeCtx, 2, rekey)
	if err != nil {
		t.Fatal(err)
	}
	notFound := decodeResponse(response)
	if notFound.Type != N_CHILD_SA_NOT_FOUND || notFound.Protocol != ProtoESP || !bytes.Equal(notFound.SPI, unknown) {
		t.Fatalf("unknown Child SA rejection = %#v", notFound)
	}
}

func TestChildRequestCreatesMissingChild(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
		skD:   []byte("test child creation SK_d material"),
	}
	s := &Session{mux: mux, current: ikeCtx}
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, 0x50607080)
	request := []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}
	response, err := s.handleChildRekey(ikeCtx, 1, request)
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response, message)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := decodeChildExchangePayloads(inner, PRF_HMAC_SHA2_256); err != nil {
		t.Fatalf("invalid Child SA creation response: %v", err)
	}
	child := s.currentChild()
	if child.LocalSPI == 0 || child.RemoteSPI != 0x50607080 || len(child.InboundKey) == 0 || len(child.OutboundKey) == 0 {
		t.Fatalf("created Child SA = %#v", child)
	}
}

func TestInformationalDeletesEveryDesignatedChildSA(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	current := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	retiring := ChildSA{LocalSPI: 0x90a0b0c0, RemoteSPI: 0xd0e0f000}
	if err := mux.RegisterESP(current.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if err := mux.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatal(err)
	}
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ikeCtx := &ikeContext{
		suite: suite,
		spiI:  0x0102030405060708,
		spiR:  0x1112131415161718,
		skei:  make([]byte, 20),
		sker:  make([]byte, 20),
	}
	s := &Session{mux: mux, current: ikeCtx, Child: current, retiring: retiring}
	var retired []uint32
	s.SetChildRetireHandler(func(localSPI uint32) error {
		retired = append(retired, localSPI)
		return nil
	})
	spi := func(value uint32) []byte {
		b := make([]byte, 4)
		binary.BigEndian.PutUint32(b, value)
		return b
	}
	response, err := s.handleRequest(ikeCtx, &Header{ExchangeType: INFORMATIONAL, MessageID: 4}, []RawPayload{
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(current.RemoteSPI), spi(0xdeadbeef)}})},
		{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi(retiring.RemoteSPI)}})},
	})
	if err != nil {
		t.Fatal(err)
	}
	message, err := DecodeMessage(response)
	if err != nil {
		t.Fatal(err)
	}
	inner, err := DecryptMessage(suite, ikeCtx.skei, response, message)
	if err != nil {
		t.Fatal(err)
	}
	if len(inner) != 1 || inner[0].Type != PayloadD {
		t.Fatalf("Delete response payloads = %#v", inner)
	}
	deleted, err := DecodeDelete(inner[0].Body)
	if err != nil {
		t.Fatal(err)
	}
	if deleted.Protocol != ProtoESP || len(deleted.SPIs) != 2 || binary.BigEndian.Uint32(deleted.SPIs[0]) != current.LocalSPI || binary.BigEndian.Uint32(deleted.SPIs[1]) != retiring.LocalSPI {
		t.Fatalf("Delete response = %#v", deleted)
	}
	if len(retired) != 2 || retired[0] != current.LocalSPI || retired[1] != retiring.LocalSPI {
		t.Fatalf("retired SPIs = %08x", retired)
	}
	if got := s.currentChild(); got.LocalSPI != 0 || got.RemoteSPI != 0 {
		t.Fatalf("current Child SA remains: %#v", got)
	}
	if got := s.retiringChild(); got.LocalSPI != 0 || got.RemoteSPI != 0 {
		t.Fatalf("retiring Child SA remains: %#v", got)
	}
	if err := other.RegisterESP(current.LocalSPI); err != nil {
		t.Fatalf("current inbound SPI remains registered: %v", err)
	}
	if err := other.RegisterESP(retiring.LocalSPI); err != nil {
		t.Fatalf("retiring inbound SPI remains registered: %v", err)
	}
}

func TestInitialResponseHeaderValidation(t *testing.T) {
	req := &Header{SPIInitiator: 1, SPIResponder: 0, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator, MessageID: 0}
	valid := &Header{SPIInitiator: 1, SPIResponder: 2, MajorVersion: 2, ExchangeType: IKE_SA_INIT, Flags: FlagResponse, MessageID: 0, Length: HeaderLen}
	if !validResponseHeader(req, valid, HeaderLen) {
		t.Fatal("valid initial response rejected")
	}
	initialError := *valid
	initialError.SPIResponder = 0
	if !validResponseHeader(req, &initialError, HeaderLen) {
		t.Fatal("valid initial error response rejected")
	}
	mutations := []func(*Header){
		func(h *Header) { h.MajorVersion = 3 }, func(h *Header) { h.ExchangeType = IKE_AUTH },
		func(h *Header) { h.Flags |= FlagInitiator },
		func(h *Header) { h.SPIInitiator++ }, func(h *Header) { h.MessageID++ },
		func(h *Header) { h.Length++ },
	}
	for i, mutate := range mutations {
		got := *valid
		mutate(&got)
		if validResponseHeader(req, &got, HeaderLen) {
			t.Errorf("invalid header mutation %d accepted: %+v", i, got)
		}
	}
}

func TestSetRekeyRetry(t *testing.T) {
	s := new(Session)
	if err := s.SetRekeyRetry(5*time.Second, time.Minute); err != nil {
		t.Fatal(err)
	}
	if s.rekeyRetryInitial != 5*time.Second || s.rekeyRetryMax != time.Minute {
		t.Fatalf("retry delays = %s, %s", s.rekeyRetryInitial, s.rekeyRetryMax)
	}
	for _, delays := range [][2]time.Duration{{0, time.Second}, {time.Second, 0}, {time.Minute, time.Second}} {
		if err := s.SetRekeyRetry(delays[0], delays[1]); err == nil {
			t.Fatalf("SetRekeyRetry(%s, %s) succeeded", delays[0], delays[1])
		}
	}
}

// Active compares against a window of seconds, so measuring it on the wall
// clock makes every session on the node flip together on any step larger than
// that: a laptop waking, an NTP correction at boot, a VM resuming. A wall step
// cannot be produced in-process, so pin the representation instead. A unix
// nanosecond timestamp is six orders of magnitude larger than any offset from
// a session's own start.
func TestLivenessClockIsOffsetRatherThanWallTimestamp(t *testing.T) {
	s := &Session{started: time.Now()}
	s.noteEstablished()
	if got := s.lastActive.Load(); got <= 0 || got > int64(time.Hour) {
		t.Fatalf("lastActive = %d, want a small offset from the session start", got)
	}
	if !s.Active() {
		t.Error("a session that has just been established reads as dead")
	}
}

func TestActiveExpiresAndComesBack(t *testing.T) {
	s := &Session{started: time.Now().Add(-time.Hour)}
	s.lastActive.Store(1) // last proof of life at the session's start
	if s.Active() {
		t.Fatal("a session last active an hour ago reads as live")
	}
	s.noteActive()
	if !s.Active() {
		t.Error("a session that just proved itself still reads as dead")
	}
}

// An exchange holds the one outstanding local request IKEv2 allows, so while
// it is open there is no rekey, no Delete on teardown and no dead peer
// detection, and the session reports up. A peer that keeps ESP flowing and
// never answers IKE, which RFC 4303 section 2.6 dummy packets alone are enough
// for, must not be able to pin it until the sequence space runs out.
func TestUnansweredExchangeStillEnds(t *testing.T) {
	ordinary := &pendingRequest{}
	for range maxRetransmits {
		ordinary.attempts = min(ordinary.attempts+1, maxRetransmits)
		ordinary.sent++
	}
	if pendingRetransmitsExhausted(ordinary, true) {
		t.Fatal("an exchange gave up at the ordinary limit while the peer was still proving it is there")
	}
	if !pendingRetransmitsExhausted(ordinary, false) {
		t.Fatal("an exchange to a silent peer did not give up at the ordinary limit")
	}
	for ordinary.sent < maxRetransmitsWhileBusy {
		ordinary.sent++
	}
	if !pendingRetransmitsExhausted(ordinary, true) {
		t.Errorf("an exchange retransmitted %d times against a peer that answers ESP and not IKE, with no end in sight", ordinary.sent)
	}

	// Dead peer detection keeps its own tighter bound, because that exchange
	// exists to decide exactly this.
	dpd := &pendingRequest{localRequest: localRequest{dpd: true}, attempts: maxRetransmits, sent: maxRetransmits}
	if !pendingRetransmitsExhausted(dpd, true) {
		t.Error("a liveness check kept retransmitting because other traffic was arriving")
	}
}

// The retirement sweep used to be reached by a hundred-millisecond poll that
// this series removed, so the loop's own deadline is now the only thing that
// brings it around. Everything else the loop waits for on an idle session is
// dead peer detection ten seconds out, so a replaced inbound SA would sit
// registered until something unrelated happened to wake the loop.
func TestRunLoopWakesForRetirement(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	retired := make(chan uint32, 1)
	s := &Session{mux: mux, current: &ikeContext{}, requests: make(chan *localRequest)}
	s.SetChildRetireHandler(func(spi uint32) error { retired <- spi; return nil })
	const spi = uint32(0x11223344)
	s.childMu.Lock()
	s.retired = append(s.retired, childRetirement{spi: spi, expiresAt: time.Now().Add(200 * time.Millisecond)})
	s.childMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	select {
	case got := <-retired:
		if got != spi {
			t.Fatalf("the sweep retired SPI %08x, which is not the one that expired, %08x", got, spi)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("the loop never woke for the retirement, so the replaced keys stay installed")
	}
	cancel()
	<-done
}

// The same wiring for a retained IKE SA. While one is held, handleIKERekey
// answers every peer-initiated rekey with TEMPORARY_FAILURE, so the loop has
// to wake for its deadline rather than leave it to whatever happens next: a
// peer that rekeys once and goes quiet produces no other event at all.
func TestRunLoopWakesForRetainedIKESA(t *testing.T) {
	mine, theirs := lifecycleMuxes(t)
	const spi = uint64(0x1122334455667788)
	replaced := &ikeContext{spiI: spi, spiR: 2}
	s := &Session{mux: mine, current: &ikeContext{spiI: 3, spiR: 4}, requests: make(chan *localRequest)}
	if err := mine.RegisterIKE(spi); err != nil {
		t.Fatal(err)
	}
	s.stateMu.Lock()
	s.old, s.oldBy = replaced, time.Now().Add(200*time.Millisecond)
	s.stateMu.Unlock()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	// Waited for on the SPI rather than on contextRetired: the flag flips
	// under stateMu and the mux is told after the unlock, so polling the flag
	// and then reading the hub reads through that window.
	deadline := time.Now().Add(5 * time.Second)
	for theirs.RegisterIKE(spi) != nil {
		if time.Now().After(deadline) {
			cancel()
			<-done
			t.Fatal("the loop never woke for the deadline, so every later peer rekey stays refused")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if !s.contextRetired(replaced) {
		t.Error("the SPI was released while the session still holds the SA it belongs to")
	}
	cancel()
	<-done
}

// A liveness probe this end cannot send is not evidence about the peer, and
// tearing the SA down for it takes every route through that peer with it. The
// attempt counter above declares a peer dead; a send that never left this node
// says nothing either way, so the loop retries on dpdRetryDelay and keeps
// serving. Reverting this closed the mux on the first probe that failed.
func TestProbeThisEndCannotSendDoesNotEndTheSession(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	// A key the AEAD will not take, so every startRequest fails inside
	// encrypt: a probe that never reaches the wire, which is the shape a
	// transport failure has from the loop's side.
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	ctx := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32),
		skei: []byte{1, 2, 3}, sker: []byte{1, 2, 3}}
	// The interval shortened so the probe is reached in milliseconds rather
	// than in the ten seconds a session uses.
	s := &Session{mux: mux, current: ctx, requests: make(chan *localRequest),
		dpdEvery: 50 * time.Millisecond}

	runCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- s.Run(runCtx) }()

	// Past the first probe and the retries behind it. dpdRetryDelay is a
	// second, so this is the first failure and two more after it.
	select {
	case err := <-done:
		t.Fatalf("a probe that could not be sent ended the session: %v", err)
	case <-time.After(s.dpdInterval() + 2*dpdRetryDelay):
	}
	if mux.IsClosed() {
		t.Error("a probe that could not be sent closed the mux, which drops every route through this peer")
	}
	cancel()
	<-done
}
