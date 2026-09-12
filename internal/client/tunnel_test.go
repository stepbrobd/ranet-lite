package client

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NickCao/ranet-lite/esp"
	"github.com/NickCao/ranet-lite/internal/transport"
)

func tunnelChild(id uint32) esp.ChildSA {
	in, out := make([]byte, 20), make([]byte, 20)
	binary.BigEndian.PutUint32(in, id)
	binary.BigEndian.PutUint32(out, id+100)
	return esp.ChildSA{EncrID: esp.ENCRAESGCM16, EncrKeyBits: 128, LocalSPI: 1000 + id, RemoteSPI: 2000 + id, InboundKey: in, OutboundKey: out}
}

func remoteSA(t *testing.T, child esp.ChildSA) *esp.OutboundSA {
	t.Helper()
	child.RemoteSPI, child.OutboundKey = child.LocalSPI, child.InboundKey
	sa, err := esp.NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	return sa
}

func sealTestPacket(t *testing.T, sa *esp.OutboundSA, id uint32) []byte {
	t.Helper()
	plain := make([]byte, 24)
	plain[0], plain[3] = 0x45, 24
	binary.BigEndian.PutUint32(plain[20:24], id)
	raw, err := sa.Seal(plain, esp.NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestTunnelRekeyPreservesInflightKeys(t *testing.T) {
	tunnel := &tunnel{replayWindow: 4096}
	old, next := tunnelChild(1), tunnelChild(2)
	if err := tunnel.install(old); err != nil {
		t.Fatal(err)
	}
	reserved, err := tunnel.reserve(1)
	if err != nil {
		t.Fatal(err)
	}
	remote := remoteSA(t, old)
	authenticated := tunnel.decryptBatch([][]byte{sealTestPacket(t, remote, 1)}, nil)[0]
	if err := tunnel.install(next); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.install(next); err == nil {
		t.Fatal("duplicate SPI installation overwrote its replay state")
	}
	// A range reserved before replacement stays bound to the old outbound SA.
	packets, err := reserved([][]byte{{1}}, []byte{esp.NextHeaderIPv4}, nil)
	if err != nil || binary.BigEndian.Uint32(packets[0][:4]) != old.RemoteSPI {
		t.Fatalf("reserved range lost its original SA: %v", err)
	}
	if err := tunnel.retire(old.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if _, _, err := authenticated.Commit(); err != nil {
		t.Fatalf("in-flight authenticated packet lost retired keys: %v", err)
	}
	for _, raw := range [][]byte{nil, {0, 1}, sealTestPacket(t, remote, 2)} {
		result := tunnel.decryptBatch([][]byte{raw}, nil)[0]
		if _, _, err := result.Commit(); err == nil {
			t.Fatal("accepted truncated data or a retired SPI")
		}
	}
	result := tunnel.decryptBatch([][]byte{sealTestPacket(t, remoteSA(t, next), 3)}, nil)[0]
	if _, _, err := result.Commit(); err != nil {
		t.Fatalf("retiring old SA disturbed the replacement: %v", err)
	}
	if err := tunnel.retire(next.LocalSPI); err != nil {
		t.Fatal(err)
	}
	if _, err := tunnel.reserve(1); err == nil {
		t.Fatal("reserved a sequence after the active Child SA was deleted")
	}
}

func TestReceiveESPOrderAndShutdown(t *testing.T) {
	for _, workers := range []int{1, 4} {
		t.Run(fmt.Sprintf("workers=%d", workers), func(t *testing.T) {
			remote, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer remote.Close()
			addr := remote.LocalAddr().(*net.UDPAddr)
			mux, err := transport.Dial(":0", addr.IP, addr.Port)
			if err != nil {
				t.Fatal(err)
			}
			defer mux.Close()
			child := tunnelChild(1)
			if err := mux.RegisterESP(child.LocalSPI); err != nil {
				t.Fatal(err)
			}
			tunnel := &tunnel{replayWindow: 4096}
			if err := tunnel.install(child); err != nil {
				t.Fatal(err)
			}
			firstStarted, releaseFirst, secondFinished := make(chan struct{}), make(chan struct{}), make(chan struct{})
			defer func() {
				select {
				case <-releaseFirst:
				default:
					close(releaseFirst)
				}
			}()
			decrypt := func(raw [][]byte, results []inboundDecrypted) []inboundDecrypted {
				if binary.BigEndian.Uint32(raw[0][4:8]) == 1 {
					close(firstStarted)
					<-releaseFirst
				} else {
					defer close(secondFinished)
				}
				return tunnel.decryptBatch(raw, results)
			}
			delivered := make(chan uint32, 2)
			done := make(chan error, 1)
			go func() {
				done <- receiveESP(mux, workers, decrypt, func(results []inboundDecrypted) {
					esp.CommitBatch(results)
					for _, result := range results {
						plain, _, err := result.Plaintext()
						if err != nil {
							t.Error(err)
							continue
						}
						delivered <- binary.BigEndian.Uint32(plain[20:24])
					}
				})
			}()
			peer := remoteSA(t, child)
			destination := &net.UDPAddr{IP: addr.IP, Port: mux.LocalAddr().(*net.UDPAddr).Port}
			if _, err := remote.WriteToUDP(sealTestPacket(t, peer, 1), destination); err != nil {
				t.Fatal(err)
			}
			select {
			case <-firstStarted:
			case <-time.After(time.Second):
				t.Fatal("first batch did not start")
			}
			if _, err := remote.WriteToUDP(sealTestPacket(t, peer, 2), destination); err != nil {
				t.Fatal(err)
			}
			if workers > 1 {
				select {
				case <-secondFinished:
				case <-time.After(time.Second):
					t.Fatal("crypto did not run concurrently")
				}
				if len(delivered) != 0 {
					t.Fatal("later crypto completion overtook the first batch")
				}
			}
			close(releaseFirst)
			for _, want := range []uint32{1, 2} {
				select {
				case got := <-delivered:
					if got != want {
						t.Fatalf("received %d, want %d", got, want)
					}
				case <-time.After(time.Second):
					t.Fatal("packet delivery stalled")
				}
			}
			_ = mux.Close()
			select {
			case <-done:
			case <-time.After(time.Second):
				t.Fatal("receiver did not join its workers on shutdown")
			}
		})
	}
}

// RFC 7296 section 1.4.1 lets a peer delete the Child SA and keep the IKE SA.
// Sending has to stop and ask for a replacement, not report the kind of error
// that closes the session: the next babel hello would otherwise tear down the
// adjacency and withdraw every route through the peer.
func TestDeletedChildSAAsksForAReplacementInsteadOfFailingHard(t *testing.T) {
	child := tunnelChild(1)
	tunnel := &tunnel{}
	asked := make(chan struct{}, 4)
	tunnel.rekey = func() { asked <- struct{}{} }
	if err := tunnel.install(child); err != nil {
		t.Fatal(err)
	}
	if err := tunnel.retire(child.LocalSPI); err != nil {
		t.Fatal(err)
	}

	_, err := tunnel.reserve(1)
	if !errors.Is(err, errNoChildSA) {
		t.Fatalf("reserve after the peer's delete = %v, want errNoChildSA", err)
	}
	select {
	case <-asked:
	case <-time.After(5 * time.Second):
		t.Fatal("no replacement Child SA was requested")
	}
}

// Every packet routed to a peer with no outbound SA reaches reserve, so the
// request has to collapse into one attempt at a time.
func TestReplacementChildSARequestsDoNotPileUp(t *testing.T) {
	tunnel := &tunnel{}
	entered := make(chan struct{}, 128)
	release := make(chan struct{})
	var running, peak atomic.Int32
	tunnel.rekey = func() {
		n := running.Add(1)
		for {
			if seen := peak.Load(); seen >= n || peak.CompareAndSwap(seen, n) {
				break
			}
		}
		entered <- struct{}{}
		<-release
		running.Add(-1)
	}
	for range 100 {
		if _, err := tunnel.reserve(1); !errors.Is(err, errNoChildSA) {
			t.Fatalf("reserve = %v, want errNoChildSA", err)
		}
	}
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("no replacement Child SA was requested")
	}
	close(release)
	if got := peak.Load(); got != 1 {
		t.Fatalf("%d concurrent rekey attempts, want exactly 1", got)
	}
}
