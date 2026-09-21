package ike

import (
	"context"
	"errors"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

func TestInitiateCancellationLeavesSharedHubOpen(t *testing.T) {
	peer := listenPeer(t)
	address := peer.LocalAddr().(*net.UDPAddr)
	hub, err := transport.NewHub(":0", transport.Underlay{}, transport.Runtime{})
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		_, err := InitiateContext(ctx, PeerConfig{RemoteAddr: address.IP, RemotePort: address.Port, Hub: hub})
		done <- err
	}()
	peer.SetReadDeadline(time.Now().Add(time.Second))
	if _, _, err := peer.ReadFromUDP(make([]byte, 4096)); err != nil {
		t.Fatal(err)
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancellation returned %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("canceled handshake is still waiting for retransmission")
	}
	mux, err := hub.NewMux(address.IP, address.Port)
	if err != nil {
		t.Fatalf("handshake cancellation closed the shared hub: %v", err)
	}
	defer mux.Close()
	if err := mux.SendIKE(encodeTestMessage(t, Header{SPIInitiator: 123, ExchangeType: IKE_SA_INIT, Flags: FlagInitiator}, nil)); err != nil {
		t.Fatalf("shared hub cannot transmit after cancellation: %v", err)
	}
}

func TestFullRangeSelectorSemantics(t *testing.T) {
	narrow := FullRangeV4()
	narrow.EndPort = 80
	reserved := fullRangeSelectors()
	reserved[1], reserved[2], reserved[3] = 1, 2, 3
	for _, test := range []struct {
		name string
		body []byte
		ok   bool
	}{
		{"canonical", fullRangeSelectors(), true},
		{"reversed", EncodeTS([]TrafficSelector{FullRangeV6(), FullRangeV4()}), true},
		{"reserved", reserved, true},
		{"duplicate", EncodeTS([]TrafficSelector{FullRangeV4(), FullRangeV4()}), false},
		{"narrowed", EncodeTS([]TrafficSelector{narrow, FullRangeV6()}), false},
		{"missing family", EncodeTS([]TrafficSelector{FullRangeV4()}), false},
		{"trailing data", append(fullRangeSelectors(), 0), false},
	} {
		t.Run(test.name, func(t *testing.T) {
			payload := &RawPayload{Body: test.body}
			if err := validateFullRangeSelectors(payload, payload); (err == nil) != test.ok {
				t.Fatalf("validation = %v; want accepted=%v", err, test.ok)
			}
		})
	}
}

// The teardown Delete gets its own retransmission budget, and the error it
// reports has to name the budget it spent: an operator reading "no response
// after 5 attempts" from an exchange that made two is being told the wrong
// thing about how long the failure took.
func TestSendRecvReportsTheBudgetItSpent(t *testing.T) {
	peer := listenPeer(t)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)
	mux, err := transport.Dial("127.0.0.1:0", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	request := (&Message{Header: Header{
		SPIInitiator: randUint64Nonzero(), ExchangeType: INFORMATIONAL,
		Flags: FlagInitiator, MessageID: 0,
	}}).Encode()

	// One attempt, so the test costs one requestTimeout rather than the full
	// budget, and the peer never answers.
	start := time.Now()
	_, err = sendRecvWithin(mux, request, 1, nil)
	if err == nil {
		t.Fatal("an unanswered exchange reported success")
	}
	if !strings.Contains(err.Error(), "after 1 attempts") {
		t.Errorf("the failure says %q, want it to name the one attempt it made", err)
	}
	if elapsed := time.Since(start); elapsed > 3*requestTimeout {
		t.Errorf("one attempt took %s, which is more than the budget it was given", elapsed)
	}
}
