package esp

import (
	"bytes"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
)

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	b, err := hex.DecodeString(value)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// RFC 7634 Appendix A publishes a complete tunnel-mode ChaCha20-Poly1305
// ESP packet. Opening its ESP wire image guards the SPI/sequence AAD, explicit
// IV, ciphertext, tag, padding, pad length, and Next Header together.
func TestRFC7634ESPWireImage(t *testing.T) {
	key := mustHex(t, "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3")
	packet := mustHex(t, "01020304000000051011121314151617"+
		"24039428b97f417e3c13753a4f05087b67c352e6a7fab1b982d466ef407ae5c6"+
		"14ee8099d52844eb61aa95dfab4c02f72aa71e7c4c4f64c9befe2facc638e8f3"+
		"cbec163fac469b502773f6fb94e664da9165b82829f641e0"+
		"76aaa8266b7fb0f7b11b369907e1ad43")
	want := mustHex(t, "45000054a6f200004001e778c6336405c000020508005b7a3a080000553bec10"+
		"0007362708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20212223"+
		"2425262728292a2b2c2d2e2f3031323334353637")
	in, err := NewInbound(ChildSA{EncrID: ENCRChaCha20Poly1305, LocalSPI: 0x01020304, InboundKey: key})
	if err != nil {
		t.Fatal(err)
	}
	plain, nextHeader, err := in.Open(packet)
	if err != nil {
		t.Fatal(err)
	}
	if nextHeader != NextHeaderIPv4 || !bytes.Equal(plain, want) {
		t.Fatalf("RFC 7634 packet decoded to next-header %d, plaintext %x", nextHeader, plain)
	}
}

// This fixed AES-GCM packet exercises RFC 4106's complete ESP construction,
// not merely a local encrypt/decrypt round trip.
func TestRFC4106ESPWireImage(t *testing.T) {
	key := mustHex(t, "000102030405060708090a0b0c0d0e0f10111213")
	want := mustHex(t, "010203040000000100000000000000010c00b9b18f251e201fc6e81e37c3b1abf1d5002d1ae464e91ab3d134327602fe5e5ec36e3774fa67")
	out, err := NewOutbound(ChildSA{EncrID: ENCRAESGCM16, EncrKeyBits: 128, RemoteSPI: 0x01020304, OutboundKey: key})
	if err != nil {
		t.Fatal(err)
	}
	got, err := out.Seal([]byte("RFC 4106 AES-GCM ESP"), NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("RFC 4106 wire image = %x", got)
	}
}

func TestProactivePacketCountRekey(t *testing.T) {
	out, err := NewOutbound(testChild(t))
	if err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	out.SetRekeyCallback(func() { called.Add(1) })
	out.seq.Store(ProactiveRekeySequence - 2)
	// One packet short of the mark asks for nothing.
	if _, err := out.Seal(nil, NextHeaderIPv4); err != nil {
		t.Fatal(err)
	}
	if got := called.Load(); got != 0 {
		t.Fatalf("rekey callback called %d times before the mark, want none", got)
	}
	// And every reservation past it asks again. A single ask for the life of
	// the SA is the one thing that cannot retry a rekey that failed, which is
	// the case ProactiveRekeySequence's margin is sized for: the next driver
	// would be the scheduled rekey, most of an hour away, while at the rates
	// in that comment the space runs out in minutes. The rate is bounded by
	// the callback, which carries the one-at-a-time guard and the floor.
	for range 3 {
		if _, err := out.Seal(nil, NextHeaderIPv4); err != nil {
			t.Fatal(err)
		}
	}
	if got := called.Load(); got != 3 {
		t.Fatalf("rekey callback called %d times past the mark, want one per reservation", got)
	}
}

// Refusing to send is right -- RFC 4303 section 3.3.3 forbids reusing a
// sequence number -- but the refusal has to be recognizable, because the
// caller's answer is to replace the SA rather than to tear the session down.
func TestExhaustionIsReportedAsItsOwnError(t *testing.T) {
	out, err := NewOutbound(testChild(t))
	if err != nil {
		t.Fatal(err)
	}
	var called atomic.Int32
	out.SetRekeyCallback(func() { called.Add(1) })
	out.seq.Store(0xffffffff)
	if _, err := out.ReserveSequenceRange(1); !errors.Is(err, ErrSequenceExhausted) {
		t.Fatalf("a spent sequence space reported %v, want ErrSequenceExhausted", err)
	}
	if got := called.Load(); got == 0 {
		t.Error("a spent sequence space asked for no replacement")
	}
}

func TestReservedSequenceRangesRemainContiguousWhenSealedOutOfOrder(t *testing.T) {
	out, err := NewOutbound(testChild(t))
	if err != nil {
		t.Fatal(err)
	}
	first, err := out.ReserveSequenceRange(2)
	if err != nil {
		t.Fatal(err)
	}
	second, err := out.ReserveSequenceRange(2)
	if err != nil {
		t.Fatal(err)
	}

	// Complete the later worker first. Reservation order, rather than
	// goroutine scheduling or AEAD completion order, determines sequences.
	var got []uint32
	for _, r := range []*SequenceRange{second, first} {
		for range 2 {
			packet, err := r.Seal(nil, NextHeaderIPv4)
			if err != nil {
				t.Fatal(err)
			}
			got = append(got, binary.BigEndian.Uint32(packet[4:8]))
		}
	}
	want := []uint32{3, 4, 1, 2}
	if !slices.Equal(got, want) {
		t.Fatalf("sealed sequences = %v, want %v", got, want)
	}
	if _, err := first.Seal(nil, NextHeaderIPv4); err == nil {
		t.Fatal("exhausted sequence range accepted another packet")
	}
}

func TestSealBatchProducesAdjacentPackets(t *testing.T) {
	out, err := NewOutbound(testChild(t))
	if err != nil {
		t.Fatal(err)
	}
	r, err := out.ReserveSequenceRange(3)
	if err != nil {
		t.Fatal(err)
	}
	packets, err := r.SealBatch(
		[][]byte{[]byte("first"), []byte("second"), []byte("tail")},
		[]byte{NextHeaderIPv4, NextHeaderIPv4, NextHeaderIPv4},
	)
	if err != nil {
		t.Fatal(err)
	}
	for i, packet := range packets {
		if got, want := binary.BigEndian.Uint32(packet[4:8]), uint32(i+1); got != want {
			t.Fatalf("packet %d sequence = %d, want %d", i, got, want)
		}
	}
	for i := 0; i+1 < len(packets); i++ {
		end := len(packets[i]) + len(packets[i+1])
		if cap(packets[i]) < end || !bytes.Equal(packets[i][:end][len(packets[i]):], packets[i+1]) {
			t.Fatalf("packets %d and %d are not adjacent", i, i+1)
		}
	}
}

func testChild(t *testing.T) ChildSA {
	t.Helper()
	key := make([]byte, 20) // AES-128-GCM: 16-byte key + 4-byte salt
	rand.Read(key)
	return ChildSA{
		EncrID: 20, EncrKeyBits: 128,
		LocalSPI: 0x11111111, RemoteSPI: 0x22222222,
		InboundKey: key, OutboundKey: key,
	}
}

func TestRoundTrip(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	}, WithReplayWindow(4096))
	if err != nil {
		t.Fatal(err)
	}

	payload := []byte("hello from the other side of the tunnel")
	pkt, err := out.Seal(payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	got, nh, err := in.Open(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if nh != NextHeaderIPv4 {
		t.Fatalf("next header = %d, want %d", nh, NextHeaderIPv4)
	}
	if !bytes.Equal(got, payload) {
		t.Fatalf("payload mismatch: got %q want %q", got, payload)
	}
}

func TestAuthenticateInPlaceReusesCiphertextStorage(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	newInbound := func() *InboundSA {
		in, err := NewInbound(ChildSA{
			EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
			LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
		})
		if err != nil {
			t.Fatal(err)
		}
		return in
	}

	payload := []byte("owned receive buffer")
	packet, err := out.Seal(payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	original := bytes.Clone(packet)
	if _, err := newInbound().Authenticate(packet); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(packet, original) {
		t.Fatal("Authenticate modified its input")
	}

	authenticated, err := newInbound().AuthenticateInPlace(packet)
	if err != nil {
		t.Fatal(err)
	}
	ciphertextStart := headerLen + out.params.IVLen
	if &authenticated.plain[0] != &packet[ciphertextStart] {
		t.Fatal("AuthenticateInPlace allocated separate plaintext storage")
	}
	plain, nextHeader, err := authenticated.Commit()
	if err != nil {
		t.Fatal(err)
	}
	if nextHeader != NextHeaderIPv4 || !bytes.Equal(plain, payload) {
		t.Fatalf("round trip mismatch: header %d, payload %q", nextHeader, plain)
	}
}

func TestAuthenticatedMalformedPacketConsumesSequence(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits, LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey})
	if err != nil {
		t.Fatal(err)
	}
	packet := make([]byte, headerLen+out.params.IVLen)
	binary.BigEndian.PutUint32(packet[0:4], out.spi)
	binary.BigEndian.PutUint32(packet[4:8], 1)
	binary.BigEndian.PutUint64(packet[8:16], 1)
	nonce := append(append([]byte(nil), out.salt...), packet[8:16]...)
	packet = out.aead.Seal(packet, nonce, []byte{0, 3, NextHeaderIPv4}, packet[:headerLen])
	if _, _, err := in.Open(packet); err == nil {
		t.Fatal("accepted malformed authenticated trailer")
	}
	in.mu.Lock()
	err = in.window.check(1)
	in.mu.Unlock()
	if err == nil {
		t.Fatal("malformed authenticated packet did not consume its sequence number")
	}
}

func TestRoundTripChaCha20Poly1305(t *testing.T) {
	key := make([]byte, 36) // 32-byte key + 4-byte salt
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	child := ChildSA{
		EncrID:   ENCRChaCha20Poly1305,
		LocalSPI: 0x11111111, RemoteSPI: 0x22222222,
		InboundKey: key, OutboundKey: key,
	}
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	payload := []byte("chacha20-poly1305 packet")
	pkt, err := out.Seal(payload, NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}
	got, nh, err := in.Open(pkt)
	if err != nil {
		t.Fatal(err)
	}
	if nh != NextHeaderIPv4 || !bytes.Equal(got, payload) {
		t.Fatalf("round trip mismatch: header %d, payload %q", nh, got)
	}
}

func TestSealAllocations(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	payload := make([]byte, 1400)
	allocs := testing.AllocsPerRun(100, func() {
		if _, err := out.Seal(payload, NextHeaderIPv4); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 1 {
		t.Fatalf("Seal allocated %.1f times per packet, want at most one output buffer", allocs)
	}

	const batchSize = 128
	batch := make([][]byte, batchSize)
	headers := make([]byte, batchSize)
	for i := range batch {
		batch[i], headers[i] = payload, NextHeaderIPv4
	}
	r := SequenceRange{sa: out}
	allocs = testing.AllocsPerRun(100, func() {
		r.next, r.end = 1, batchSize
		if _, err := r.SealBatch(batch, headers); err != nil {
			t.Fatal(err)
		}
	})
	if allocs > 2 {
		t.Fatalf("SealBatch allocated %.1f times per batch, want one packet vector and one output buffer", allocs)
	}
}

func TestReplayRejected(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	pkt, _ := out.Seal([]byte("one"), NextHeaderIPv4)
	if _, _, err := in.Open(pkt); err != nil {
		t.Fatalf("first delivery should succeed: %v", err)
	}
	if _, _, err := in.Open(pkt); err == nil {
		t.Fatal("replayed packet was accepted")
	}
}

func TestAuthenticatedPacketsCommitInReceiveOrder(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	if err != nil {
		t.Fatal(err)
	}

	packets := make([][]byte, 64)
	for i := range packets {
		packets[i], err = out.Seal([]byte{byte(i)}, NextHeaderIPv4)
		if err != nil {
			t.Fatal(err)
		}
	}

	// Model a later worker completing first. Authentication alone must not
	// advance the replay window far enough to reject the earlier batch.
	later, err := in.Authenticate(packets[len(packets)-1])
	if err != nil {
		t.Fatal(err)
	}
	earlier, err := in.Authenticate(packets[0])
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := earlier.Commit(); err != nil {
		t.Fatalf("commit earlier packet: %v", err)
	}
	if _, _, err := later.Commit(); err != nil {
		t.Fatalf("commit later packet: %v", err)
	}
}

func TestAuthenticatedPacketCommitRejectsReplay(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	packet, _ := out.Seal([]byte("one"), NextHeaderIPv4)
	first, err := in.Authenticate(packet)
	if err != nil {
		t.Fatal(err)
	}
	duplicate, err := in.Authenticate(packet)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := first.Commit(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := duplicate.Commit(); err == nil {
		t.Fatal("second commit of an authenticated replay succeeded")
	}
}

// TestReplayWindowWideReordering exercises the multi-word bitmap directly
// (bypassing real ESP/AEAD): sequences arriving thousands of positions out
// of order, as observed in practice under highly parallel real-world
// traffic (e.g. iperf3 -P 8 sharing one SA's sequence space across
// multiple flows/CPU cores), must still be accepted as long as they're
// within the replay window — and exact duplicates, even far apart across a large
// window advance, must still be rejected.
func TestReplayWindowWideReordering(t *testing.T) {
	const window = 4096
	w := newReplayWindow(window)

	// Establish a high watermark.
	if err := w.check(10000); err != nil {
		t.Fatalf("first packet should be accepted: %v", err)
	}
	w.commit(10000)

	// A packet ~3000 sequence numbers behind is well within a 64-packet
	// window's rejection range but must be accepted by the wider window.
	late := uint32(10000 - 3000)
	if err := w.check(late); err != nil {
		t.Fatalf("packet %d positions behind should be accepted with a %d window: %v", 3000, window, err)
	}
	w.commit(late)

	// The same late packet replayed again must still be rejected.
	if err := w.check(late); err == nil {
		t.Fatal("exact duplicate of a far-behind packet was accepted")
	}

	// A packet further behind than the window must be rejected as too old.
	tooOld := uint32(10000 - window - 1)
	if err := w.check(tooOld); err == nil {
		t.Fatal("packet beyond the window was accepted")
	}

	// Advancing last by more than the window (a large jump forward, e.g.
	// after a burst) must not retain stale bits from before the jump: a
	// sequence that was legitimately received just before the jump must
	// now correctly read as "too old" rather than incorrectly "already
	// seen" or accepted twice.
	w.commit(10000 + window + 500)
	if err := w.check(10000); err == nil {
		t.Fatal("a sequence far behind after a large jump should be rejected as too old, not silently accepted")
	}
}

func TestReplayWindowZeroDisablesChecking(t *testing.T) {
	w := newReplayWindow(0)
	if err := w.check(0); err != nil {
		t.Fatalf("disabled replay window rejected sequence zero: %v", err)
	}
	w.commit(0)
}

// TestSealConcurrentUniqueSeq guards the split between atomic sequence
// allocation and the actual AEAD compute (unlocked, safe for concurrent use) in
// Seal: many goroutines sealing concurrently must never collide on a
// sequence number/IV, and the receiver must decrypt every one of them
// (Open, run sequentially here, doesn't care what order Seal calls
// completed in — only that all resulting sequence numbers are distinct
// and within the replay window relative to each other).
func TestSealConcurrentUniqueSeq(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	}, WithReplayWindow(4096))
	if err != nil {
		t.Fatal(err)
	}

	const n = 200
	pkts := make([][]byte, n)
	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			pkt, err := out.Seal([]byte(fmt.Sprintf("packet-%d", i)), NextHeaderIPv4)
			if err != nil {
				t.Errorf("Seal: %v", err)
				return
			}
			pkts[i] = pkt
		}(i)
	}
	wg.Wait()

	seen := map[uint32]bool{}
	for i, pkt := range pkts {
		if pkt == nil {
			continue
		}
		seq := binary.BigEndian.Uint32(pkt[4:8])
		if seen[seq] {
			t.Fatalf("packet %d: sequence number %d reused", i, seq)
		}
		seen[seq] = true
		if _, _, err := in.Open(pkt); err != nil {
			t.Fatalf("packet %d (seq %d): %v", i, seq, err)
		}
	}
	if len(seen) != n {
		t.Fatalf("got %d distinct sequence numbers, want %d", len(seen), n)
	}
}

// TestOpenConcurrent seals a batch of distinct packets up front (as a
// single-threaded sender would), then opens all of them concurrently —
// exercising Open's locked-check/unlocked-decrypt/locked-recheck-commit
// split under the race detector. Every packet must decrypt successfully
// exactly once.
func TestOpenConcurrent(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	}, WithReplayWindow(4096))
	if err != nil {
		t.Fatal(err)
	}

	const n = 200
	pkts := make([][]byte, n)
	for i := range pkts {
		pkt, err := out.Seal([]byte(fmt.Sprintf("packet-%d", i)), NextHeaderIPv4)
		if err != nil {
			t.Fatal(err)
		}
		pkts[i] = pkt
	}

	var wg sync.WaitGroup
	var mu sync.Mutex
	var failed int
	for _, pkt := range pkts {
		wg.Add(1)
		go func(pkt []byte) {
			defer wg.Done()
			if _, _, err := in.Open(pkt); err != nil {
				mu.Lock()
				failed++
				mu.Unlock()
				t.Errorf("concurrent Open: %v", err)
			}
		}(pkt)
	}
	wg.Wait()
	if failed != 0 {
		t.Fatalf("%d/%d concurrent opens failed", failed, n)
	}
}

// TestOpenConcurrentReplayRejected races many goroutines opening the
// *exact same* packet simultaneously: exactly one must succeed (the
// first-check optimization racing the second locked check-and-commit
// must never let two winners through).
func TestOpenConcurrentReplayRejected(t *testing.T) {
	child := testChild(t)
	out, err := NewOutbound(child)
	if err != nil {
		t.Fatal(err)
	}
	in, err := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	if err != nil {
		t.Fatal(err)
	}
	pkt, err := out.Seal([]byte("replay me"), NextHeaderIPv4)
	if err != nil {
		t.Fatal(err)
	}

	const n = 50
	var wg sync.WaitGroup
	var successes atomic.Int32
	for range n {
		wg.Go(func() {
			if _, _, err := in.Open(pkt); err == nil {
				successes.Add(1)
			}
		})
	}
	wg.Wait()
	if got := successes.Load(); got != 1 {
		t.Fatalf("got %d successful opens of the same packet, want exactly 1", got)
	}
}

func TestTamperedPacketRejected(t *testing.T) {
	child := testChild(t)
	out, _ := NewOutbound(child)
	in, _ := NewInbound(ChildSA{
		EncrID: child.EncrID, EncrKeyBits: child.EncrKeyBits,
		LocalSPI: child.RemoteSPI, InboundKey: child.OutboundKey,
	})
	pkt, _ := out.Seal([]byte("untouched"), NextHeaderIPv4)
	pkt[len(pkt)-1] ^= 0xff
	if _, _, err := in.Open(pkt); err == nil {
		t.Fatal("tampered packet was accepted")
	}
}

// RFC 4303 section 2.4 right-aligns the Pad Length and Next Header octets in a
// four-byte word, so a conformant sender's plaintext is always a multiple of
// four. Taking anything else accepts a payload no sender should have produced,
// and this end's own padding follows the same rule.
func TestPlaintextMustBeFourByteAligned(t *testing.T) {
	// Twenty bytes of payload, two of padding, then the Pad Length and Next
	// Header octets: twenty-four, a multiple of four.
	aligned := make([]byte, 24)
	aligned[0] = 0x45
	// RFC 4303 section 2.4 numbers the padding 1..n.
	aligned[20], aligned[21] = 1, 2
	aligned[22], aligned[23] = 2, 4
	if _, _, err := parseTrailer(aligned); err != nil {
		t.Fatalf("a four-byte aligned plaintext was refused: %v", err)
	}
	for _, length := range []int{1, 2, 3, 5, 6, 7} {
		plain := make([]byte, length)
		if length >= 2 {
			plain[length-1] = 4
		}
		if _, _, err := parseTrailer(plain); err == nil {
			t.Errorf("a %d byte plaintext was accepted, and no conformant sender produces one", length)
		}
	}
}

// RFC 4303 section 2.4 makes the sender's numbering a MUST when the encryption
// algorithm specifies no padding contents of its own, which neither RFC 4106
// nor RFC 7634 does, and makes the receiver's inspection a SHOULD. The check is
// inside the ICV, so what it catches is a sender this end does not understand
// rather than an attacker, and an interop failure here is far easier to read
// as "invalid padding contents" than as a packet that decrypts to nonsense.
func TestPaddingContentsFollowTheSectionThatDefinesThem(t *testing.T) {
	plaintext := func(pad ...byte) []byte {
		out := make([]byte, 0, 4+len(pad)+2)
		out = append(out, 0x45, 0, 0, 0)
		out = append(out, pad...)
		return append(out, byte(len(pad)), 4)
	}
	if _, _, err := parseTrailer(plaintext(1, 2)); err != nil {
		t.Fatalf("the sequence the section names was refused: %v", err)
	}
	for name, pad := range map[string][]byte{
		"zeroes":             {0, 0},
		"counting from zero": {0, 1},
		"repeated":           {1, 1},
		"reversed":           {2, 1},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseTrailer(plaintext(pad...)); err == nil {
				t.Error("padding no conformant sender produces was accepted")
			}
		})
	}
	// That this end's own sender produces what its receiver takes is already
	// what every round trip in this package shows.
}
