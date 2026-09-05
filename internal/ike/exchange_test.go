package ike

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/internal/transport"
)

func TestInitiateCancellationLeavesSharedHubOpen(t *testing.T) {
	peer := listenPeer(t)
	address := peer.LocalAddr().(*net.UDPAddr)
	hub, err := transport.NewHub(":0")
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
		t.Fatal("cancelled handshake is still waiting for retransmission")
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
