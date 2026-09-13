package transport

import (
	"encoding/binary"
	"errors"
	"net"
	"runtime"
	"testing"
	"time"
)

// listenPeer opens a plain UDP socket standing in for "the peer" at the
// far end of a Mux, on the given loopback address (v4 or v6) — used to
// verify what a Mux actually puts on the wire without needing a second
// Mux/full IKE session.
func listenPeer(t *testing.T, network, addr string) *net.UDPConn {
	t.Helper()
	conn, err := net.ListenUDP(network, &net.UDPAddr{IP: net.ParseIP(addr)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { conn.Close() })
	return conn
}

func testSendESPBatch(t *testing.T, network, addr string) {
	peer := listenPeer(t, network, addr)
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	// A batch larger than Bind's limit exercises sendESPLoop's splitting and
	// pending-batch handling as well as the ordinary batched send path.
	const n = 200
	batch := make([][]byte, n)
	for i := 0; i < n; i++ {
		batch[i] = []byte{byte(i), byte(i >> 8)}
	}
	if err := m.SendESPBatch(batch); err != nil {
		t.Fatalf("SendESPBatch: %v", err)
	}

	got := map[int]bool{}
	buf := make([]byte, 64)
	peer.SetReadDeadline(time.Now().Add(5 * time.Second))
	for i := 0; i < n; i++ {
		rn, _, err := peer.ReadFromUDP(buf)
		if err != nil {
			t.Fatalf("read %d/%d: %v", i, n, err)
		}
		if rn != 2 {
			t.Fatalf("unexpected packet length %d, want 2", rn)
		}
		got[int(buf[0])|int(buf[1])<<8] = true
	}
	if len(got) != n {
		t.Fatalf("got %d distinct packets, want %d", len(got), n)
	}
}

func TestSendESPBatchIPv4(t *testing.T) {
	testSendESPBatch(t, "udp4", "127.0.0.1")
}

func TestSendESPBatchIPv6(t *testing.T) {
	testSendESPBatch(t, "udp6", "::1")
}

func TestPackReceivedBatchDetachesReusableBuffers(t *testing.T) {
	first := []byte("first")
	second := []byte("second")
	packets := packReceivedBatch([][]byte{first, second})

	first[0] = 'x'
	second[0] = 'y'
	if string(packets[0]) != "first" || string(packets[1]) != "second" {
		t.Fatalf("packed packets changed with receive buffers: got %q", packets)
	}

	packets[0][0] = 'F'
	if packets[1][0] != 's' {
		t.Fatalf("packet boundaries overlap: got %q", packets)
	}
}

func TestHubFailureIsTerminal(t *testing.T) {
	hub, err := NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	mux, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4500)
	if err != nil {
		t.Fatal(err)
	}
	cause := errors.New("receive failed")
	hub.fail(cause)

	if _, err := mux.RecvESP(); !errors.Is(err, cause) {
		t.Fatalf("existing mux error = %v, want %v", err, cause)
	}
	if _, err := hub.NewMux(net.IPv4(127, 0, 0, 1), 4501); err == nil {
		t.Fatal("failed hub accepted a new mux")
	}
	if err := hub.Close(); err != nil {
		t.Fatalf("second terminal transition returned an error: %v", err)
	}
}

func TestRecvESPBatchDrainsToDestinationCapacity(t *testing.T) {
	m := &Mux{espCh: make(chan espDatagramBatch, 2), done: make(chan struct{})}
	m.espCh <- espDatagramBatch{packets: [][]byte{[]byte("one"), []byte("two")}}
	m.espCh <- espDatagramBatch{packets: [][]byte{[]byte("three")}}

	batch, err := m.RecvESPBatch(make([][]byte, 0, 2))
	if err != nil {
		t.Fatal(err)
	}
	if len(batch) != 2 || string(batch[0]) != "one" || string(batch[1]) != "two" {
		t.Fatalf("batch = %q, want [one two]", batch)
	}
	last, err := m.RecvESP()
	if err != nil {
		t.Fatal(err)
	}
	if string(last) != "three" {
		t.Fatalf("remaining packet = %q, want three", last)
	}
}

func TestConcurrentESPReceiveCarriesDispatchOrder(t *testing.T) {
	m := &Mux{espCh: make(chan espDatagramBatch, 2), done: make(chan struct{})}
	if !m.dispatchESP([][]byte{[]byte("first")}, len("first")) || !m.dispatchESP([][]byte{[]byte("second")}, len("second")) {
		t.Fatal("dispatch unexpectedly dropped a batch")
	}

	type received struct {
		ticket  uint64
		packets [][]byte
		err     error
	}
	results := make(chan received, 2)
	for range 2 {
		go func() {
			ticket, packets, err := m.RecvESPBatchConcurrent()
			results <- received{ticket: ticket, packets: packets, err: err}
		}()
	}
	byTicket := make(map[uint64]string, 2)
	for range 2 {
		got := <-results
		if got.err != nil {
			t.Fatal(got.err)
		}
		byTicket[got.ticket] = string(got.packets[0])
	}
	if byTicket[0] != "first" || byTicket[1] != "second" {
		t.Fatalf("received tickets = %v, want map[0:first 1:second]", byTicket)
	}
}

func TestDroppedESPBatchDoesNotLeaveTicketGap(t *testing.T) {
	m := &Mux{espCh: make(chan espDatagramBatch, 1), done: make(chan struct{})}
	if !m.dispatchESP([][]byte{[]byte("accepted")}, len("accepted")) {
		t.Fatal("first dispatch was dropped")
	}
	if m.dispatchESP([][]byte{[]byte("dropped")}, len("dropped")) {
		t.Fatal("dispatch to a full queue succeeded")
	}
	if _, _, err := m.RecvESPBatchConcurrent(); err != nil {
		t.Fatal(err)
	}
	if !m.dispatchESP([][]byte{[]byte("next")}, len("next")) {
		t.Fatal("dispatch after draining was dropped")
	}
	ticket, _, err := m.RecvESPBatchConcurrent()
	if err != nil {
		t.Fatal(err)
	}
	if ticket != 1 {
		t.Fatalf("ticket after a dropped batch = %d, want 1", ticket)
	}
}

// TestSendIKEUnbatchedAndMarked confirms SendIKE still writes immediately
// (not queued through the ESP batching path) and always carries the
// 4-byte non-ESP marker, including for what would be the very first
// IKE_SA_INIT request.
func TestSendIKEUnbatchedAndMarked(t *testing.T) {
	peer := listenPeer(t, "udp4", "127.0.0.1")
	peerAddr := peer.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", peerAddr.IP, peerAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()

	payload := []byte("fake ike header")
	if err := m.SendIKE(payload); err != nil {
		t.Fatal(err)
	}

	buf := make([]byte, 64)
	peer.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("SendIKE should be written immediately, not queued: %v", err)
	}
	if n != nonESPMarkerLen+len(payload) {
		t.Fatalf("got %d bytes, want %d", n, nonESPMarkerLen+len(payload))
	}
	for _, b := range buf[:nonESPMarkerLen] {
		if b != 0 {
			t.Fatalf("expected a 4-byte zero marker, got %x", buf[:nonESPMarkerLen])
		}
	}
	if string(buf[nonESPMarkerLen:n]) != string(payload) {
		t.Fatalf("payload mismatch: got %q want %q", buf[nonESPMarkerLen:n], payload)
	}
}

func TestSendIKEToReceivedSourceEndpoint(t *testing.T) {
	configured := listenPeer(t, "udp4", "127.0.0.1")
	rebound := listenPeer(t, "udp4", "127.0.0.1")
	configuredAddr := configured.LocalAddr().(*net.UDPAddr)
	m, err := Dial("", configuredAddr.IP, configuredAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	const spiI = uint64(0x0102030405060708)
	if err := m.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: m.LocalAddr().(*net.UDPAddr).Port}
	request := make([]byte, 28)
	binary.BigEndian.PutUint64(request[:8], spiI)
	if _, err := rebound.WriteToUDP(withMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	_, source, err := m.RecvIKEFromUntil(time.Now().Add(time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if err := m.SendIKETo([]byte("response"), source); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	rebound.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := rebound.ReadFromUDP(buf)
	if err != nil || string(buf[nonESPMarkerLen:n]) != "response" {
		t.Fatalf("rebound endpoint response = %q, %v", buf[:n], err)
	}
	m.AdoptEndpoint(source)
	if err := m.SendIKE([]byte("future")); err != nil {
		t.Fatal(err)
	}
	rebound.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err = rebound.ReadFromUDP(buf)
	if err != nil || string(buf[nonESPMarkerLen:n]) != "future" {
		t.Fatalf("adopted endpoint response = %q, %v", buf[:n], err)
	}
	configured.SetReadDeadline(time.Now().Add(20 * time.Millisecond))
	if _, _, err := configured.ReadFromUDP(buf); err == nil {
		t.Fatal("response was also sent to the stale configured endpoint")
	}
}

func withMarker(payload []byte) []byte {
	return append(make([]byte, nonESPMarkerLen), payload...)
}

func testRecvESPBatch(t *testing.T, network, addr string) {
	server := listenPeer(t, network, addr)
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	m, err := Dial("", serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.RegisterESP(0xaabbccdd); err != nil {
		t.Fatal(err)
	}
	clientAddr := m.LocalAddr().(*net.UDPAddr)
	// LocalAddr() on this Mux is wildcard-bound ("::" or "0.0.0.0"), which
	// isn't a valid destination — send to the actual loopback address the
	// test is using instead, at the port Dial picked.
	dst := &net.UDPAddr{IP: net.ParseIP(addr), Port: clientAddr.Port}

	// Sent back-to-back with no synchronization, so receiveLoop's batch read
	// has a real chance to pick up more than one of these in a single
	// call — this is the actual code path under test.
	const n = 200
	for i := 0; i < n; i++ {
		pkt := []byte{0xaa, 0xbb, 0xcc, 0xdd, byte(i), byte(i >> 8), 0, 1}
		if _, err := server.WriteToUDP(pkt, dst); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}

	got := map[int]bool{}
	for i := 0; i < n; i++ {
		pkt, err := m.RecvESP()
		if err != nil {
			t.Fatalf("RecvESP %d/%d: %v", i, n, err)
		}
		got[int(pkt[4])|int(pkt[5])<<8] = true
	}
	if len(got) != n {
		t.Fatalf("got %d distinct packets, want %d", len(got), n)
	}
}

func TestRecvESPBatchIPv4(t *testing.T) {
	testRecvESPBatch(t, "udp4", "127.0.0.1")
}

func TestRecvESPBatchIPv6(t *testing.T) {
	testRecvESPBatch(t, "udp6", "::1")
}

// TestRecvESPAndIKEDemux confirms the receive-side demux (marker present
// -> IKE, absent -> ESP) still works correctly regardless of whether the
// sender used a batched or unbatched write — it's a plain UDP receiver on
// this end either way, unaffected by how the peer chose to send.
func TestRecvESPAndIKEDemux(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	serverAddr := server.LocalAddr().(*net.UDPAddr)

	// Dial always binds all interfaces regardless of what's passed here
	// (see Dial's doc comment) -- LocalAddr()'s IP is unspecified, only its
	// port is meaningful, so the destination below is built from the
	// known loopback address plus that port, not from LocalAddr() directly.
	m, err := Dial(":0", serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.RegisterESP(0xaabbccdd); err != nil {
		t.Fatal(err)
	}
	if err := m.RegisterIKE(0x696b650000000000); err != nil {
		t.Fatal(err)
	}

	clientAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: m.LocalAddr().(*net.UDPAddr).Port}
	espPkt := []byte{0xaa, 0xbb, 0xcc, 0xdd, 0, 0, 0, 1, 'e', 's', 'p'}
	if _, err := server.WriteToUDP(espPkt, clientAddr); err != nil {
		t.Fatal(err)
	}
	ikePkt := append([]byte{0, 0, 0, 0}, append([]byte("ike"), make([]byte, 5)...)...)
	if _, err := server.WriteToUDP(ikePkt, clientAddr); err != nil {
		t.Fatal(err)
	}

	got, err := m.RecvESP()
	if err != nil {
		t.Fatalf("RecvESP: %v", err)
	}
	if string(got) != string(espPkt) {
		t.Fatalf("ESP payload mismatch: got %x want %x", got, espPkt)
	}
	gotIKE, err := m.RecvIKE()
	if err != nil {
		t.Fatalf("RecvIKE: %v", err)
	}
	if string(gotIKE[:3]) != "ike" {
		t.Fatalf("IKE payload mismatch: got %q want %q", gotIKE[:3], "ike")
	}
}

func TestHubRoutesBySPIAndMuxCloseDoesNotCloseHub(t *testing.T) {
	server := listenPeer(t, "udp4", "127.0.0.1")
	serverAddr := server.LocalAddr().(*net.UDPAddr)
	hub, err := NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	first, err := hub.NewMux(serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	second, err := hub.NewMux(serverAddr.IP, serverAddr.Port)
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	if err := first.RegisterIKE(1); err != nil {
		t.Fatal(err)
	}
	if err := second.RegisterESP(2); err != nil {
		t.Fatal(err)
	}

	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	ikePkt := append([]byte{0, 0, 0, 0}, append([]byte{0, 0, 0, 0, 0, 0, 0, 1}, []byte("ike")...)...)
	if _, err := server.WriteToUDP(ikePkt, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := first.RecvIKEUntil(time.Now().Add(time.Second)); err != nil || string(got) != string(ikePkt[4:]) {
		t.Fatalf("RecvIKE = %x, %v", got, err)
	}
	if err := first.Close(); err != nil {
		t.Fatal(err)
	}

	espPkt := []byte{0, 0, 0, 2, 'e', 's', 'p'}
	if _, err := server.WriteToUDP(espPkt, dst); err != nil {
		t.Fatal(err)
	}
	if got, err := second.RecvESPUntil(time.Now().Add(time.Second)); err != nil || string(got) != string(espPkt) {
		t.Fatalf("RecvESP = %x, %v", got, err)
	}
}

func TestListenDeliversUnclaimedIKEAndNewMuxToAnswers(t *testing.T) {
	h, err := NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	defer h.Close()
	unclaimed := h.Listen()

	peer := listenPeer(t, "udp4", "127.0.0.1")
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: h.LocalAddr().(*net.UDPAddr).Port}
	const spiI = uint64(0x1122334455667788)
	request := make([]byte, 28)
	binary.BigEndian.PutUint64(request[:8], spiI)
	if _, err := peer.WriteToUDP(withMarker(request), dst); err != nil {
		t.Fatal(err)
	}

	var first Unclaimed
	select {
	case first = <-unclaimed:
	case <-time.After(time.Second):
		t.Fatal("unclaimed IKE datagram was not delivered")
	}
	if binary.BigEndian.Uint64(first.Raw[:8]) != spiI {
		t.Fatalf("unclaimed SPI = %x", first.Raw[:8])
	}

	// A responder learns the peer's address only from this datagram, so the
	// mux it answers on is created from the endpoint rather than from config.
	m, err := h.NewMuxTo(first.Endpoint)
	if err != nil {
		t.Fatal(err)
	}
	defer m.Close()
	if err := m.RegisterIKE(spiI); err != nil {
		t.Fatal(err)
	}
	if err := m.SendIKE([]byte("response")); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 64)
	peer.SetReadDeadline(time.Now().Add(time.Second))
	n, _, err := peer.ReadFromUDP(buf)
	if err != nil || string(buf[nonESPMarkerLen:n]) != "response" {
		t.Fatalf("response = %q, %v", buf[:n], err)
	}

	// Once registered, the same SPI reaches the mux instead of the listener.
	if _, err := peer.WriteToUDP(withMarker(request), dst); err != nil {
		t.Fatal(err)
	}
	if _, _, err := m.RecvIKEFromUntil(time.Now().Add(time.Second)); err != nil {
		t.Fatalf("registered SPI did not reach the mux: %v", err)
	}
	select {
	case <-unclaimed:
		t.Fatal("a claimed SPI was still delivered to the listener")
	default:
	}
}

func TestHubDoneIsClosedOnFailure(t *testing.T) {
	h, err := NewHub(":0")
	if err != nil {
		t.Fatal(err)
	}
	h.Listen()
	if err := h.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-h.Done():
	case <-time.After(time.Second):
		t.Fatal("Done was not closed")
	}
}

// An ESP SPI is cleartext on the wire and the receive queue is filled before
// anything is authenticated, so whoever has seen one packet from a peer can
// aim a flood at it. The batch count bounds nothing on its own: one batch
// holds up to espSendBatch datagrams of up to readBufferSize each.
func TestESPReceiveQueueIsBoundedInBytes(t *testing.T) {
	m := &Mux{espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
	packet := make([]byte, 1<<16)
	queued, accepted := 0, 0
	for range espChanSize {
		if !m.hasRoomForESP(len(packet)) {
			break
		}
		if !m.dispatchESP([][]byte{packet}, len(packet)) {
			break
		}
		queued += len(packet)
		accepted++
	}
	if accepted == espChanSize {
		t.Fatal("the queue filled to its batch count, so nothing bounded its bytes")
	}
	if queued > espQueueBytes {
		t.Fatalf("the queue holds %d bytes, want at most %d", queued, espQueueBytes)
	}

	// Draining has to give the budget back, or the queue shrinks to nothing
	// over the life of a session.
	for range accepted {
		if _, _, err := m.RecvESPBatchConcurrent(); err != nil {
			t.Fatal(err)
		}
	}
	if got := m.espQueued.Load(); got != 0 {
		t.Fatalf("%d bytes are still charged after the queue drained", got)
	}
	if !m.hasRoomForESP(len(packet)) {
		t.Fatal("a drained queue still reports itself full")
	}
}

// Every receive path has to release the budget, not just the concurrent one.
func TestEveryESPReceivePathReleasesItsBudget(t *testing.T) {
	for name, recv := range map[string]func(*Mux) error{
		"RecvESP":      func(m *Mux) error { _, err := m.RecvESP(); return err },
		"RecvESPBatch": func(m *Mux) error { _, err := m.RecvESPBatch(nil); return err },
		"RecvESPUntil": func(m *Mux) error {
			_, err := m.RecvESPUntil(time.Now().Add(time.Second))
			return err
		},
		"RecvESPBatchConcurrent": func(m *Mux) error { _, _, err := m.RecvESPBatchConcurrent(); return err },
	} {
		t.Run(name, func(t *testing.T) {
			m := &Mux{espCh: make(chan espDatagramBatch, 4), done: make(chan struct{})}
			payload := []byte("one whole datagram")
			if !m.dispatchESP([][]byte{payload}, len(payload)) {
				t.Fatal("dispatch was dropped")
			}
			if err := recv(m); err != nil {
				t.Fatal(err)
			}
			if got := m.espQueued.Load(); got != 0 {
				t.Fatalf("%d bytes are still charged after %s drained the batch", got, name)
			}
		})
	}
}

// Hub.Listen's contract is that a full queue drops the datagram rather than
// blocking the receive loop, because an unauthenticated peer must not be able
// to stall the dataplane. The copy onto the heap has to come after that
// decision, or the flood is paid for in allocation whether it is kept or not.
func TestFloodOfUnclaimedIKEDatagramsIsNotCopied(t *testing.T) {
	hub, err := NewHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	unclaimed := hub.Listen()

	peer := listenPeer(t, "udp4", "127.0.0.1")
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	// An IKE_SA_INIT-shaped datagram for an SA no mux owns, at the largest
	// size a single UDP datagram carries on loopback.
	datagram := withMarker(make([]byte, 8192))
	binary.BigEndian.PutUint64(datagram[nonESPMarkerLen:], 0x1122334455667788)

	var allocated uint64
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 2000 {
		if _, err := peer.WriteToUDP(datagram, dst); err != nil {
			t.Fatal(err)
		}
	}
	// Give the receive loop time to drop what it cannot keep.
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(unclaimed) < cap(unclaimed) {
		time.Sleep(5 * time.Millisecond)
	}
	runtime.ReadMemStats(&after)
	allocated = after.TotalAlloc - before.TotalAlloc

	// The queue holds a bounded number, and everything past it costs nothing but
	// the receive buffer it already had. Copying every datagram would be
	// 2000 * 8192 bytes, so half of that separates the two outcomes by a wide
	// margin in both directions and leaves room for whatever else a sandbox
	// allocates while this runs.
	if budget := uint64(2000*len(datagram)) / 2; allocated > budget {
		t.Errorf("a flood of %d dropped datagrams allocated %d bytes, want well under %d",
			2000, allocated, budget)
	}
}

// The same contract one layer in. A peer that has completed a handshake has a
// mux, so its datagrams are demultiplexed onto that mux's own queue and never
// reach Hub.Listen: the flood that costs something is aimed at ikeCh, which
// holds sixteen. The copy has to come after the queue is tested there too.
func TestFloodOnMuxIKEQueueIsNotCopied(t *testing.T) {
	hub, err := NewHub("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer hub.Close()
	mux, err := hub.NewMux(net.ParseIP("127.0.0.1"), 9)
	if err != nil {
		t.Fatal(err)
	}
	defer mux.Close()
	const spi = uint64(0x1122334455667788)
	if err := mux.RegisterIKE(spi); err != nil {
		t.Fatal(err)
	}

	peer := listenPeer(t, "udp4", "127.0.0.1")
	dst := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: hub.LocalAddr().(*net.UDPAddr).Port}
	datagram := withMarker(make([]byte, 8192))
	binary.BigEndian.PutUint64(datagram[nonESPMarkerLen:], spi)

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for range 2000 {
		if _, err := peer.WriteToUDP(datagram, dst); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) && len(mux.IKE()) < cap(mux.IKE()) {
		time.Sleep(5 * time.Millisecond)
	}
	runtime.ReadMemStats(&after)
	allocated := after.TotalAlloc - before.TotalAlloc

	// ikeCh holds sixteen, so everything past that costs nothing but the
	// receive buffer the loop already had. Copying every datagram would be
	// 2000 * 8192 bytes, and half of that separates the two outcomes widely in
	// both directions.
	if budget := uint64(2000*len(datagram)) / 2; allocated > budget {
		t.Errorf("a flood of %d dropped datagrams allocated %d bytes, want well under %d",
			2000, allocated, budget)
	}
}

// The byte bound is enforced twice and the two are not interchangeable.
// dispatchESP decides, under the same lock the receive-order ticket is taken
// with, which is what makes it right when a hub's IPv4 and IPv6 receive loops
// arrive at once. hasRoomForESP is consulted before packReceivedBatch copies,
// so a batch that is about to be dropped is never paid for. A test that calls
// the two in sequence and stops on whichever refuses first cannot say which
// one is enforcing, so each is driven alone here.
func TestEachESPByteBoundRefusesOnItsOwn(t *testing.T) {
	packet := make([]byte, 1<<16)
	t.Run("dispatchESP", func(t *testing.T) {
		m := &Mux{espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
		accepted := 0
		// Deliberately not consulting hasRoomForESP: this is the check that
		// has to hold on its own.
		for range espChanSize {
			if !m.dispatchESP([][]byte{packet}, len(packet)) {
				break
			}
			accepted++
		}
		if accepted == espChanSize {
			t.Fatal("the queue filled to its batch count, so dispatchESP bounded no bytes")
		}
		if got := m.espQueued.Load(); got > espQueueBytes {
			t.Fatalf("the queue holds %d bytes, want at most %d", got, espQueueBytes)
		}
	})
	t.Run("hasRoomForESP", func(t *testing.T) {
		m := &Mux{espCh: make(chan espDatagramBatch, espChanSize), done: make(chan struct{})}
		// Charged the way a queued batch charges it, without going through
		// dispatchESP, so only the pre-copy check can notice.
		m.espQueued.Store(espQueueBytes - int64(len(packet)))
		if !m.hasRoomForESP(len(packet)) {
			t.Error("a batch that exactly fits was refused")
		}
		if m.hasRoomForESP(len(packet) + 1) {
			t.Error("a batch one byte past the budget was accepted")
		}
		m.espQueued.Store(espQueueBytes)
		if m.hasRoomForESP(1) {
			t.Error("a full queue accepted another byte")
		}
	})
}
