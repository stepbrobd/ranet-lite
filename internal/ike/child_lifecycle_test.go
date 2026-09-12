package ike

import (
	"bytes"
	"encoding/binary"
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

func TestChildNegotiationUsesRequestIKEKeys(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	old := &ikeContext{suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}, skD: bytes.Repeat([]byte{1}, 32)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest)}
	done := make(chan error, 1)
	go func() { done <- s.negotiateChild(nil) }()
	req := <-s.requests
	// A peer IKE rekey can finish before the Child response is processed.
	s.stateMu.Lock()
	s.current = &ikeContext{suite: old.suite, skD: bytes.Repeat([]byte{2}, 32)}
	s.stateMu.Unlock()
	nonce := make([]byte, 32)
	req.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoESP, SPI: []byte{1, 2, 3, 4}, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}}}})},
		{Type: PayloadNonce, Body: nonce},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	wantOut, wantIn, err := ChildSAKeymat(old.suite.PRFID, old.skD, findType(req.inner, PayloadNonce).Body, nonce, ENCR_AES_GCM_16, 128)
	if err != nil {
		t.Fatal(err)
	}
	child := s.currentChild()
	if !bytes.Equal(child.OutboundKey, wantOut) || !bytes.Equal(child.InboundKey, wantIn) {
		t.Fatal("Child SA used the replacement IKE SA's keys instead of its request context")
	}
}

func lifecycleMuxes(t *testing.T) (*transport.Mux, *transport.Mux) {
	t.Helper()
	hub, err := transport.NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { hub.Close() })
	first, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4501)
	if err != nil {
		t.Fatal(err)
	}
	return first, second
}

func TestReplaceChildRollsBackSPIRegistration(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	s := &Session{mux: mux}
	s.SetChildHandler(func(ChildSA) error { return errors.New("install failed") })
	child := ChildSA{LocalSPI: 0x10203040}
	if err := s.replaceChild(child); err == nil {
		t.Fatal("replaceChild succeeded after handler failure")
	}
	if err := other.RegisterESP(child.LocalSPI); err != nil {
		t.Fatalf("failed installation retained SPI registration: %v", err)
	}
}

func TestReplaceChildDoesNotReuseInstalledSPI(t *testing.T) {
	for _, draining := range []bool{false, true} {
		mux, other := lifecycleMuxes(t)
		s := &Session{mux: mux}
		if err := mux.RegisterESP(42); err != nil {
			t.Fatal(err)
		}
		if draining {
			s.retired = []childRetirement{{spi: 42}}
		} else {
			s.Child.LocalSPI = 42
		}
		if err := s.replaceChild(ChildSA{LocalSPI: 42}); err == nil {
			t.Fatal("reused an SPI whose inbound keys are still installed")
		}
		if err := other.RegisterESP(42); err == nil {
			t.Fatal("failed replacement released the existing SPI registration")
		}
	}
}

func TestRetireChildPreservesRetryableStateOnFailure(t *testing.T) {
	mux, other := lifecycleMuxes(t)
	old := ChildSA{LocalSPI: 0x10203040, RemoteSPI: 0x50607080}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{mux: mux, retiring: old}
	s.SetChildRetireHandler(func(uint32) error { return errors.New("remove failed") })
	if err := s.retireChild(old.RemoteSPI); err == nil {
		t.Fatal("retireChild succeeded after handler failure")
	}
	if got := s.retiringChild(); got.LocalSPI != old.LocalSPI || got.RemoteSPI != old.RemoteSPI {
		t.Fatalf("retiring Child SA changed after failure: got %+v, want %+v", got, old)
	}
	if err := other.RegisterESP(old.LocalSPI); err == nil {
		t.Fatal("failed retirement released the inbound SPI")
	}

	s.SetChildRetireHandler(func(uint32) error { return nil })
	if err := s.retireChild(old.RemoteSPI); err != nil {
		t.Fatal(err)
	}
	if err := other.RegisterESP(old.LocalSPI); err != nil {
		t.Fatalf("successful retirement retained SPI registration: %v", err)
	}
}

func TestReplaceChildRejectsOverlappingRetirement(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{mux: mux, retiring: ChildSA{LocalSPI: 1, RemoteSPI: 2}}
	if err := s.replaceChild(ChildSA{LocalSPI: 3, RemoteSPI: 4}); err == nil {
		t.Fatal("replaceChild replaced an SA while an earlier one was still retiring")
	}
}

func TestRekeyRetirementAllowsQueuedESPToDrain(t *testing.T) {
	for _, peerDelete := range []bool{false, true} {
		mux, other := lifecycleMuxes(t)
		old := ChildSA{LocalSPI: 1, RemoteSPI: 2}
		if err := mux.RegisterESP(old.LocalSPI); err != nil {
			t.Fatal(err)
		}
		s := &Session{mux: mux, retiring: old, childRetireDelay: time.Second}
		removed := false
		s.SetChildRetireHandler(func(spi uint32) error {
			if spi != old.LocalSPI {
				t.Fatalf("retired SPI = %d, want %d", spi, old.LocalSPI)
			}
			removed = true
			return nil
		})
		var err error
		if peerDelete {
			_, err = s.deleteChildren([]uint32{old.RemoteSPI})
		} else {
			err = s.retireChild(old.RemoteSPI)
		}
		if err != nil {
			t.Fatal(err)
		}
		if removed || s.retiringChild().LocalSPI != 0 {
			t.Fatal("retirement removed inbound keys immediately or blocked the next rekey")
		}
		if err := other.RegisterESP(old.LocalSPI); err == nil {
			t.Fatal("inbound SPI was released before queued ESP could drain")
		}
		deadline := s.retired[0].expiresAt
		if err := s.expireRetiredChildren(deadline.Add(-time.Nanosecond)); err != nil || removed {
			t.Fatalf("expired inbound SA too early: %v", err)
		}
		if err := s.expireRetiredChildren(deadline); err != nil || !removed {
			t.Fatalf("did not remove expired inbound SA: %v", err)
		}
		if err := other.RegisterESP(old.LocalSPI); err != nil {
			t.Fatalf("expired inbound SPI is still registered: %v", err)
		}
	}
}

func TestProactiveChildRekeyCoalescesWithRunningExchange(t *testing.T) {
	s := new(Session)
	s.childRekeying.Store(true)
	if err := s.RekeyChildProactively(); err != nil {
		t.Fatalf("proactive rekey did not coalesce: %v", err)
	}
	if err := s.RekeyChild(); err == nil {
		t.Fatal("ordinary rekey did not report the running exchange")
	}
}

func TestChildRekeyGuardSerializesAttempts(t *testing.T) {
	s := &Session{}
	if !s.childRekeying.CompareAndSwap(false, true) {
		t.Fatal("failed to reserve Child rekey")
	}
	if s.childRekeying.CompareAndSwap(false, true) {
		t.Fatal("reserved a second simultaneous Child rekey")
	}
}

func TestChildNotFoundRecoveryCreatesNewChild(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x10203040, RemoteSPI: 0x50607080,
	}
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skD:   []byte("test child replacement SK_d material"),
		},
		Child:    old,
		requests: make(chan *localRequest),
	}
	var retired uint32
	s.SetChildRetireHandler(func(localSPI uint32) error {
		retired = localSPI
		return nil
	})
	var installed ChildSA
	s.SetChildHandler(func(child ChildSA) error {
		installed = child
		return nil
	})

	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()
	first := <-s.requests
	rekeyPayload := findType(first.inner, PayloadN)
	if first.exchange != CREATE_CHILD_SA || rekeyPayload == nil {
		t.Fatalf("first request is not a Child SA rekey: %#v", first.inner)
	}
	rekey, err := DecodeNotify(rekeyPayload.Body)
	if err != nil || rekey.Type != N_REKEY_SA || binary.BigEndian.Uint32(rekey.SPI) != old.LocalSPI {
		t.Fatalf("first REKEY_SA = %#v, %v", rekey, err)
	}
	missingSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(missingSPI, old.LocalSPI)
	first.result <- requestResult{inner: []RawPayload{{
		Type: PayloadN,
		Body: EncodeNotify(Notify{Protocol: ProtoESP, SPI: missingSPI, Type: N_CHILD_SA_NOT_FOUND}),
	}}}

	second := <-s.requests
	if second.exchange != CREATE_CHILD_SA || findType(second.inner, PayloadN) != nil {
		t.Fatalf("replacement request still contains REKEY_SA: %#v", second.inner)
	}
	requestPayloads, err := decodeChildExchangePayloads(second.inner)
	if err != nil {
		t.Fatalf("invalid replacement request: %v", err)
	}
	proposals, err := DecodeSA(requestPayloads.sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("invalid replacement proposal: %#v, %v", proposals, err)
	}
	newLocalSPI := binary.BigEndian.Uint32(proposals[0].SPI)
	newRemoteSPI := uint32(0x90a0b0c0)
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, newRemoteSPI)
	second.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if retired != old.LocalSPI {
		t.Fatalf("retired SPI = %08x, want %08x", retired, old.LocalSPI)
	}
	if installed.LocalSPI != newLocalSPI || installed.RemoteSPI != newRemoteSPI {
		t.Fatalf("installed Child SA = %#v", installed)
	}
	if got := s.currentChild(); got.LocalSPI != newLocalSPI || got.RemoteSPI != newRemoteSPI {
		t.Fatalf("current Child SA = %#v", got)
	}
}

// requestMu orders callers queueing work for Run; it does not order Run
// itself, which allocates Message IDs on its own goroutine. A session closed
// the instant it is established runs both at once, which is what adopt's
// replace path produces on a simultaneous open.
func TestLocalMessageIDIsNotAllocatedTwiceAtOnce(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite:        SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skei:         make([]byte, 20),
			sker:         make([]byte, 20),
			nextLocalMID: 2,
		},
		requests: make(chan *localRequest),
	}

	payloads := []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}}
	seen := make(chan uint32, 64)
	var senders sync.WaitGroup
	for range 8 {
		senders.Go(func() { _ = s.sendUnansweredRequest(payloads) })
		senders.Go(func() {
			pending, err := s.startRequest(&localRequest{exchange: INFORMATIONAL, inner: payloads, result: make(chan requestResult, 1)})
			if err == nil {
				seen <- pending.msgID
			}
		})
	}
	senders.Wait()
	close(seen)

	taken := make(map[uint32]bool)
	for msgID := range seen {
		if taken[msgID] {
			t.Fatalf("Message ID %d was handed to two exchanges", msgID)
		}
		taken[msgID] = true
	}
}

// driveChildRekey runs one Child SA rekey to the point where the replacement
// is installed and the INFORMATIONAL Delete for the old SA is outstanding,
// and answers that Delete with respond.
func driveChildRekey(t *testing.T, s *Session, old ChildSA, respond func(*localRequest)) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- s.RekeyChild() }()

	rekey := <-s.requests
	payloads, err := decodeChildExchangePayloads(rekey.inner)
	if err != nil {
		t.Fatalf("invalid rekey request: %v", err)
	}
	proposals, err := DecodeSA(payloads.sa.Body)
	if err != nil || len(proposals) != 1 || len(proposals[0].SPI) != 4 {
		t.Fatalf("invalid rekey proposal: %#v, %v", proposals, err)
	}
	remoteSPI := make([]byte, 4)
	binary.BigEndian.PutUint32(remoteSPI, old.RemoteSPI+1)
	rekey.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{
			Number: 1, Protocol: ProtoESP, SPI: remoteSPI,
			Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransESN, ID: ESN_NO}},
		}})},
		{Type: PayloadNonce, Body: EncodeNonce(make([]byte, 32))},
		{Type: PayloadTSi, Body: fullRangeSelectors()},
		{Type: PayloadTSr, Body: fullRangeSelectors()},
	}}

	remove := <-s.requests
	if remove.exchange != INFORMATIONAL {
		t.Fatalf("second exchange = %d, want INFORMATIONAL", remove.exchange)
	}
	respond(remove)
	return <-done
}

func newRekeyableSession(t *testing.T, old ChildSA) *Session {
	t.Helper()
	mux, _ := lifecycleMuxes(t)
	if err := mux.RegisterESP(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	s := &Session{
		mux: mux,
		current: &ikeContext{
			suite: SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256},
			skD:   []byte("test child replacement SK_d material"),
		},
		Child:    old,
		requests: make(chan *localRequest),
	}
	s.SetChildHandler(func(ChildSA) error { return nil })
	s.SetChildRetireHandler(func(uint32) error { return nil })
	return s
}

// RFC 7296 section 1.4.1 requires a peer whose own Delete crossed ours to
// answer with no Delete payload at all. Treating that as a failure used to
// leave the replaced SA latched in s.retiring, which locks out every later
// rekey in both directions for the life of the session.
func TestCrossedChildDeleteStillRetiresTheReplacedSA(t *testing.T) {
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x10203040, RemoteSPI: 0x50607080,
	}
	s := newRekeyableSession(t, old)
	if err := driveChildRekey(t, s, old, func(remove *localRequest) {
		remove.result <- requestResult{inner: nil}
	}); err != nil {
		t.Fatalf("rekey: %v", err)
	}
	if got := s.retiringChild(); got.LocalSPI != 0 {
		t.Fatalf("Child SA %08x is still awaiting retirement", got.LocalSPI)
	}

	// The session has to stay rekeyable, which is the part a latch broke.
	next := s.currentChild()
	if err := driveChildRekey(t, s, next, func(remove *localRequest) {
		spi := make([]byte, 4)
		binary.BigEndian.PutUint32(spi, next.RemoteSPI)
		remove.result <- requestResult{inner: []RawPayload{
			{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoESP, SPIs: [][]byte{spi}})},
		}}
	}); err != nil {
		t.Fatalf("second rekey: %v", err)
	}
}

// A failed retire exchange has nobody left to send the Delete either, so the
// replaced SA still has to come out of s.retiring.
func TestFailedChildRetireExchangeStillClearsTheReplacedSA(t *testing.T) {
	old := ChildSA{
		EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128,
		LocalSPI: 0x11223344, RemoteSPI: 0x55667788,
	}
	s := newRekeyableSession(t, old)
	err := driveChildRekey(t, s, old, func(remove *localRequest) {
		remove.result <- requestResult{err: errors.New("peer stopped answering")}
	})
	if err == nil {
		t.Fatal("a failed retire exchange should still be reported")
	}
	if got := s.retiringChild(); got.LocalSPI != 0 {
		t.Fatalf("Child SA %08x is still awaiting retirement after a failed exchange", got.LocalSPI)
	}
}
