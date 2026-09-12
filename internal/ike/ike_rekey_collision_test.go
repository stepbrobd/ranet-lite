package ike

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

func TestLosingLocalIKERekeyAcceptsDeleteResponse(t *testing.T) {
	mux, _ := lifecycleMuxes(t)
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	s := &Session{mux: mux, current: old, requests: make(chan *localRequest, 1), ikeRekeyNonce: func(n []byte) error {
		copy(n, bytes.Repeat([]byte{1}, len(n)))
		return nil
	}}
	done := make(chan error, 1)
	go func() { done <- s.RekeyIKE() }()
	request := <-s.requests
	dh, err := GenerateDH(DH_CURVE25519)
	if err != nil {
		t.Fatal(err)
	}
	winner := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
	s.stateMu.Lock()
	s.collision = winner
	s.localRekey.peerNonce = bytes.Repeat([]byte{2}, 32)
	s.localRekey.peerResponseNonce = bytes.Repeat([]byte{2}, 32)
	s.stateMu.Unlock()
	spi := make([]byte, 8)
	binary.BigEndian.PutUint64(spi, 22)
	request.result <- requestResult{inner: []RawPayload{
		{Type: PayloadSA, Body: EncodeSA([]Proposal{{Number: 1, Protocol: ProtoIKE, SPI: spi, Transforms: []Transform{{Type: TransEncr, ID: ENCR_AES_GCM_16, KeyLengthBits: 128}, {Type: TransPRF, ID: PRF_HMAC_SHA2_256}, {Type: TransDH, ID: DH_CURVE25519}}}})},
		{Type: PayloadNonce, Body: bytes.Repeat([]byte{1}, 32)},
		{Type: PayloadKE, Body: EncodeKE(DH_CURVE25519, dh.PublicBytes())},
	}}
	deleteRequest := <-s.requests
	pending, err := s.startRequest(deleteRequest)
	if err != nil {
		t.Fatal(err)
	}
	c := deleteRequest.context
	response, err := EncryptMessage(c.suite, c.peerEncryptionKey(), Header{SPIInitiator: c.spiI, SPIResponder: c.spiR, ExchangeType: INFORMATIONAL, Flags: FlagResponse, MessageID: pending.msgID}, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	// The peer may retire the original IKE SA while our redundant-SA Delete
	// is still outstanding. Completing that Delete must not resurrect it.
	s.removeRetainedContext(old)
	if !s.dispatch(response, nil, &pending) {
		deleteRequest.result <- requestResult{err: fmt.Errorf("test cleanup")}
		<-done
		t.Fatal("valid Delete response for the losing local IKE SA was discarded")
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	current, retained := s.contexts()
	if current != winner || retained != nil || s.collision != nil {
		t.Fatal("collision did not retain only the winning IKE SA")
	}
}

// RFC 7296 section 2.8.2: "If the peer that did notice the simultaneous rekey
// gets the delete request from the other peer for the old IKE SA, it knows
// that the other peer did not detect the simultaneous rekey, and the first
// peer can forget its own rekey attempt." Closing the session instead throws
// away an SA the peer believes is current.
func TestOneSidedIKERekeyCollisionAdoptsThePeersSA(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: 11, spiR: 12, skD: make([]byte, 32), skei: make([]byte, 20), sker: make([]byte, 20)}
	peerSA := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
	s := &Session{current: old}
	// Only this end noticed: the peer's new SA is held as the collision
	// candidate while this end's own rekey is still outstanding.
	s.collision = peerSA
	s.localRekey = &ikeRekey{old: old, nonce: make([]byte, 32)}

	if !s.adoptCollisionOnPeerDelete(old) {
		t.Fatal("the peer's Delete for the old SA closed the session instead of resolving the collision")
	}
	if s.current != peerSA {
		t.Errorf("current SA is %p, want the peer's %p", s.current, peerSA)
	}
	if s.collision != nil || s.localRekey != nil {
		t.Error("the abandoned local rekey attempt was not forgotten")
	}
	// It applies only to that case: a Delete on any other SA still ends the
	// session, and so does one with no collision outstanding.
	if s.adoptCollisionOnPeerDelete(old) {
		t.Error("a second Delete for the replaced SA resolved a collision that is over")
	}
}

// The same case driven through the path a real Delete takes, because the
// resolution above is only reached if dispatch asks for it.
func TestPeerDeleteOnAOneSidedCollisionKeepsTheSessionOpen(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()

	const spiI, spiR = 0x0102030405060708, 0x1112131415161718
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	old := &ikeContext{suite: suite, spiI: spiI, spiR: spiR, skei: make([]byte, 20), sker: make([]byte, 20)}
	peerSA := &ikeContext{suite: suite, spiI: 31, spiR: 32, responder: true}
	s := &Session{mux: mux, current: old, collision: peerSA, localRekey: &ikeRekey{old: old, nonce: make([]byte, 32)}}
	if err := mux.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}

	del, err := EncryptMessage(suite, old.sker, Header{
		SPIInitiator: spiI, SPIResponder: spiR, ExchangeType: INFORMATIONAL, MessageID: 0,
	}, nil, []RawPayload{{Type: PayloadD, Body: EncodeDelete(Delete{Protocol: ProtoIKE})}})
	if err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: mux.LocalAddr().(*net.UDPAddr).Port}
	if _, err := peer.WriteToUDP(withNonESPMarker(del), dst); err != nil {
		t.Fatal(err)
	}
	raw, source, err := mux.RecvIKEFromUntil(time.Now().Add(5 * time.Second))
	if err != nil {
		t.Fatal(err)
	}
	var pending *pendingRequest
	if !s.dispatch(raw, source, &pending) {
		t.Fatal("the peer's Delete was not authenticated")
	}
	if mux.IsClosed() {
		t.Fatal("the peer's Delete for the SA it replaced closed the whole session")
	}
	if s.current != peerSA {
		t.Errorf("current SA is %p, want the peer's %p", s.current, peerSA)
	}
}

// An exchange whose IKE SA has gone can never be answered, and IKEv2 permits
// one outstanding local request at a time, so leaving it pending stops every
// later rekey and the Delete on teardown for the life of the session.
func TestARequestOnARetiredIKESAIsFailedRatherThanLeftPending(t *testing.T) {
	suite := SASuite{EncrID: ENCR_AES_GCM_16, EncrKeyBits: 128, PRFID: PRF_HMAC_SHA2_256}
	current := &ikeContext{suite: suite, spiI: 11, spiR: 12}
	retired := &ikeContext{suite: suite, spiI: 21, spiR: 22}
	s := &Session{current: current}
	if s.contextRetired(current) {
		t.Error("the current SA reports as retired")
	}
	if !s.contextRetired(retired) {
		t.Error("an SA this session no longer holds reports as live")
	}
	s.old, s.collision = retired, nil
	if s.contextRetired(retired) {
		t.Error("a retained old SA reports as retired")
	}
	s.old, s.collision = nil, retired
	if s.contextRetired(retired) {
		t.Error("a retained collision candidate reports as retired")
	}
}
