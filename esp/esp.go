// Package esp implements userspace ESP (RFC 4303) tunnel-mode AEAD
// encapsulation/decapsulation for exactly the Child SA negotiated by
// package ike: AES-GCM or ChaCha20-Poly1305, no ESN, one SA per direction.
// Peer-initiated Child SA rekeys replace these instances in the production
// data plane. Packets are carried UDP-encapsulated (RFC 3948) since ranet's
// strongSwan deployments force that unconditionally; see
// internal/transport.Mux for the shared socket.
package esp

import (
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"sync"
	"sync/atomic"
)

const (
	NextHeaderIPv4 = 4
	NextHeaderIPv6 = 41
	NextHeaderNone = 59

	headerLen = 8 // SPI + 32-bit Sequence Number
	// ProactiveRekeySequence leaves a 65536-packet safety margin before a
	// non-ESN SA's sequence space is exhausted.
	ProactiveRekeySequence = uint64(0xffffffff - 0xffff)
)

// OutboundSA encrypts packets for the direction this client originates.
// Sequence/IV assignment is atomic because Babel and the mesh may reserve
// packets from separate goroutines. Reusing a sequence/IV with AES-GCM would
// break confidentiality and authentication outright.
type OutboundSA struct {
	aead   cipher.AEAD
	params aeadParams
	salt   []byte
	spi    uint32

	seq       atomic.Uint64 // next sequence number to use; 0 is never sent (RFC 4303 §2.2)
	rekeyOnce sync.Once
	onRekey   func()
}

// SequenceRange is an ordered run of sequence numbers reserved from one SA.
// A range belongs to one worker: successive Seal calls consume its sequence
// numbers in order, while separate ranges can perform their AEAD work in
// parallel. Values can only be created by OutboundSA.ReserveSequenceRange, so
// callers cannot accidentally choose or reuse a nonce.
type SequenceRange struct {
	sa   *OutboundSA
	next uint64
	end  uint64
}

// SetRekeyCallback installs a one-shot notification fired when the outbound
// packet counter reaches ProactiveRekeySequence. Configure it before Seal is
// called concurrently.
func (o *OutboundSA) SetRekeyCallback(fn func()) { o.onRekey = fn }

// InboundSA decrypts packets sent to this client's SPI. Authentication checks
// the replay window before AEAD work; committing checks it again atomically
// with advancing the window. AEAD always runs outside the replay mutex.
type InboundSA struct {
	aead   cipher.AEAD
	params aeadParams
	salt   []byte
	spi    uint32

	mu     sync.Mutex
	window replayWindow
}

// AuthenticatedPacket carries an authentication result until its replay check
// is committed. Receive workers authenticate in parallel, then the ordered
// emitter calls CommitBatch and Plaintext. Its zero value cannot be accepted.
// Each result belongs to one worker or emitter at a time.
type AuthenticatedPacket struct {
	sa         *InboundSA
	seq        uint32
	committed  bool
	nextHeader byte
	plain      []byte
	Err        error
}

// InboundOption configures inbound ESP processing.
type InboundOption func(*InboundSA)

// WithReplayWindow sets the anti-replay window. A zero value disables replay
// checking, matching strongSwan's replay_window = 0 behavior.
func WithReplayWindow(window uint32) InboundOption {
	return func(in *InboundSA) { in.window = newReplayWindow(window) }
}

func NewOutbound(child ChildSA) (*OutboundSA, error) {
	aead, params, err := newESPAEAD(child.EncrID, child.EncrKeyBits, child.OutboundKey)
	if err != nil {
		return nil, err
	}
	return &OutboundSA{
		aead: aead, params: params,
		salt: child.OutboundKey[params.keyLen:],
		spi:  child.RemoteSPI,
	}, nil
}

func NewInbound(child ChildSA, options ...InboundOption) (*InboundSA, error) {
	aead, params, err := newESPAEAD(child.EncrID, child.EncrKeyBits, child.InboundKey)
	if err != nil {
		return nil, err
	}
	in := &InboundSA{
		aead: aead, params: params,
		salt:   child.InboundKey[params.keyLen:],
		spi:    child.LocalSPI,
		window: newReplayWindow(DefaultReplayWindow),
	}
	for _, option := range options {
		option(in)
	}
	return in, nil
}

// Seal wraps one tunnel-mode IP packet (nextHeader identifies its version,
// NextHeaderIPv4/IPv6) into a full ESP packet ready for UDP encapsulation.
// It is the single-packet convenience path; the data plane reserves ranges so
// whole TUN batches can encrypt concurrently without allocating their ESP
// sequence numbers in scheduler-dependent order.
func (o *OutboundSA) Seal(innerIPPacket []byte, nextHeader byte) ([]byte, error) {
	seq, _, err := o.reserveSequenceNumbers(1)
	if err != nil {
		return nil, err
	}
	nonceLen := o.aead.NonceSize()
	storage := make([]byte, nonceLen, nonceLen+o.sealedLen(len(innerIPPacket)))
	storage = o.appendSealed(storage, storage[:nonceLen], innerIPPacket, nextHeader, seq)
	return storage[nonceLen:], nil
}

// ReserveSequenceRange atomically reserves count consecutive ESP sequence
// numbers. Reserving is cheap and may be serialized with packet intake; the
// returned range performs the expensive AEAD operations later and in parallel
// with other ranges.
func (o *OutboundSA) ReserveSequenceRange(count int) (*SequenceRange, error) {
	first, end, err := o.reserveSequenceNumbers(count)
	if err != nil {
		return nil, err
	}
	return &SequenceRange{sa: o, next: first, end: end}, nil
}

func (o *OutboundSA) reserveSequenceNumbers(count int) (uint64, uint64, error) {
	if count <= 0 {
		return 0, 0, fmt.Errorf("esp: sequence range must contain at least one packet")
	}
	n := uint64(count)
	end := o.seq.Add(n)
	first := end - n + 1
	if end >= ProactiveRekeySequence && first <= 0xffffffff && o.onRekey != nil {
		o.rekeyOnce.Do(o.onRekey)
	}
	if end > 0xffffffff {
		// No ESN: do not return even the in-range prefix of a reservation that
		// crosses the boundary. The caller must move the whole batch to a fresh
		// SA rather than partially transmitting it.
		return 0, 0, fmt.Errorf("esp: sequence number space exhausted, SA must be re-established")
	}
	return first, end, nil
}

// Seal consumes the next sequence number in this range and encrypts one
// tunnel-mode packet. A SequenceRange is deliberately single-worker; parallel
// callers should reserve separate ranges from the OutboundSA.
func (r *SequenceRange) Seal(innerIPPacket []byte, nextHeader byte) ([]byte, error) {
	if r == nil || r.sa == nil || r.next > r.end {
		return nil, fmt.Errorf("esp: reserved sequence range exhausted")
	}
	seq := r.next
	r.next++
	nonceLen := r.sa.aead.NonceSize()
	storage := make([]byte, nonceLen, nonceLen+r.sa.sealedLen(len(innerIPPacket)))
	storage = r.sa.appendSealed(storage, storage[:nonceLen], innerIPPacket, nextHeader, seq)
	return storage[nonceLen:], nil
}

// SealBatch consumes the rest of the range and encrypts it into one backing
// allocation. Besides reducing allocator traffic, the adjacent packet slices
// let the UDP transport use GSO without first repacking the ciphertext.
func (r *SequenceRange) SealBatch(innerIPPackets [][]byte, nextHeaders []byte) ([][]byte, error) {
	if r == nil || r.sa == nil || len(innerIPPackets) != len(nextHeaders) {
		return nil, fmt.Errorf("esp: invalid sequence batch")
	}
	if r.next > r.end || uint64(len(innerIPPackets)) != r.end-r.next+1 {
		return nil, fmt.Errorf("esp: sequence batch has %d packets, range has %d", len(innerIPPackets), r.end-r.next+1)
	}
	total := 0
	for _, packet := range innerIPPackets {
		total += r.sa.sealedLen(len(packet))
	}
	nonceLen := r.sa.aead.NonceSize()
	storage := make([]byte, nonceLen, nonceLen+total)
	nonce := storage[:nonceLen]
	sealed := make([][]byte, 0, len(innerIPPackets))
	for i, packet := range innerIPPackets {
		start := len(storage)
		storage = r.sa.appendSealed(storage, nonce, packet, nextHeaders[i], r.next)
		r.next++
		sealed = append(sealed, storage[start:])
	}
	return sealed, nil
}

func (o *OutboundSA) sealedLen(innerLen int) int {
	const trailerLen = 2 // pad length + next header octets
	padLen := (4 - (innerLen+trailerLen)%4) % 4
	return headerLen + o.params.IVLen + innerLen + padLen + trailerLen + o.params.ICVLen
}

func (o *OutboundSA) appendSealed(dst, nonce, innerIPPacket []byte, nextHeader byte, seq uint64) []byte {
	const trailerLen = 2 // pad length + next header octets
	total := len(innerIPPacket) + trailerLen
	padLen := (4 - total%4) % 4

	framingLen := headerLen + o.params.IVLen
	plainLen := len(innerIPPacket) + padLen + trailerLen
	packetLen := framingLen + plainLen + o.params.ICVLen
	start := len(dst)
	// Callers reserve the complete output capacity before encrypting. Extending
	// the slice avoids a temporary zero buffer under race instrumentation.
	dst = dst[:start+packetLen]
	out := dst[start : start+framingLen+plainLen]
	binary.BigEndian.PutUint32(out[0:4], o.spi)
	binary.BigEndian.PutUint32(out[4:8], uint32(seq))
	binary.BigEndian.PutUint64(out[8:framingLen], seq) // unique per packet, monotonic

	plain := out[framingLen:]
	copy(plain, innerIPPacket)
	for i := 1; i <= padLen; i++ {
		plain[len(innerIPPacket)+i-1] = byte(i)
	}
	plain[len(plain)-2] = byte(padLen)
	plain[len(plain)-1] = nextHeader

	copy(nonce, o.salt)
	copy(nonce[len(o.salt):], out[headerLen:framingLen])
	aad := out[:headerLen]
	sealed := o.aead.Seal(out[:framingLen], nonce, plain, aad)
	return dst[:start+len(sealed)]
}
