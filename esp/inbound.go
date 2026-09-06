package esp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"slices"
)

var (
	errUnauthenticated = errors.New("esp: packet was not authenticated")
	errUncommitted     = errors.New("esp: packet replay check was not committed")
	errCommitted       = errors.New("esp: packet was already committed")
)

// Authenticate validates the SPI and AEAD tag without advancing the replay
// window. The ciphertext is preserved. Commit must precede plaintext delivery.
func (in *InboundSA) Authenticate(pkt []byte) (*AuthenticatedPacket, error) {
	return in.authenticate(pkt, false)
}

// AuthenticateInPlace decrypts over pkt's ciphertext. The caller must own pkt
// and must not use its encrypted contents again. Use AuthenticateBatchInPlace
// to amortize replay locking and nonce storage across a batch.
func (in *InboundSA) AuthenticateInPlace(pkt []byte) (*AuthenticatedPacket, error) {
	return in.authenticate(pkt, true)
}

func (in *InboundSA) checkHeader(pkt []byte) (uint32, error) {
	if len(pkt) < headerLen+in.params.IVLen+in.params.ICVLen {
		return 0, fmt.Errorf("esp: packet too short")
	}
	if spi := binary.BigEndian.Uint32(pkt[:4]); spi != in.spi {
		return 0, fmt.Errorf("esp: SPI mismatch (got %08x, want %08x)", spi, in.spi)
	}
	return binary.BigEndian.Uint32(pkt[4:8]), nil
}

func (in *InboundSA) authenticate(pkt []byte, inPlace bool) (*AuthenticatedPacket, error) {
	seq, err := in.checkHeader(pkt)
	if err != nil {
		return nil, err
	}
	in.mu.Lock()
	err = in.window.check(seq)
	in.mu.Unlock()
	if err != nil {
		return nil, err
	}
	var nonce [12]byte
	plain, err := in.decrypt(pkt, inPlace, nonce[:])
	if err != nil {
		return nil, err
	}
	return &AuthenticatedPacket{sa: in, seq: seq, plain: plain}, nil
}

func (in *InboundSA) decrypt(pkt []byte, inPlace bool, nonce []byte) ([]byte, error) {
	iv := pkt[headerLen : headerLen+in.params.IVLen]
	ciphertext := pkt[headerLen+in.params.IVLen:]
	copy(nonce, in.salt)
	copy(nonce[len(in.salt):], iv)
	var dst []byte
	if inPlace {
		dst = ciphertext[:0]
	}
	plain, err := in.aead.Open(dst, nonce, ciphertext, pkt[:headerLen])
	if err != nil {
		return nil, fmt.Errorf("esp: authentication failed: %w", err)
	}
	return plain, nil
}

// AuthenticateBatchInPlace appends one result per packet in receive order.
// Results and ciphertext storage belong to the caller and may be reused only
// after their consumer finishes. Errors are recorded per packet; invalid input
// never advances replay state or prevents other packets from authenticating.
func (in *InboundSA) AuthenticateBatchInPlace(packets [][]byte, results []AuthenticatedPacket) []AuthenticatedPacket {
	start := len(results)
	results = slices.Grow(results, len(packets))[:start+len(packets)]
	batch := results[start:]
	in.mu.Lock()
	for i, pkt := range packets {
		seq, err := in.checkHeader(pkt)
		if err == nil {
			err = in.window.check(seq)
		}
		batch[i] = AuthenticatedPacket{sa: in, seq: seq, Err: err}
	}
	in.mu.Unlock()
	// cipher.AEAD's interface makes nonce storage escape. One buffer per batch
	// avoids a heap allocation per packet without sharing it between workers.
	var nonce [12]byte
	for i := range batch {
		if batch[i].Err == nil {
			batch[i].plain, batch[i].Err = in.decrypt(packets[i], true, nonce[:])
		}
	}
	return results
}

// CommitBatch advances replay state in slice order, taking the mutex once per
// consecutive run of packets from the same SA. The slice may span multiple SAs
// during rekey overlap. Authentication failures, duplicates, and invalid ESP
// trailers retain their individual errors. Call Plaintext to read each result.
func CommitBatch(packets []AuthenticatedPacket) {
	for len(packets) > 0 {
		sa := packets[0].sa
		end := 1
		for end < len(packets) && packets[end].sa == sa {
			end++
		}
		if sa != nil {
			sa.mu.Lock()
		}
		for i := range end {
			packets[i].commitLocked()
		}
		if sa != nil {
			sa.mu.Unlock()
		}
		packets = packets[end:]
	}
}

func (p *AuthenticatedPacket) commitLocked() {
	if p.committed {
		p.Err = errCommitted
		return
	}
	p.committed = true
	if p.Err != nil {
		return
	}
	if p.sa == nil {
		p.Err = errUnauthenticated
		return
	}
	if p.Err = p.sa.window.check(p.seq); p.Err != nil {
		return
	}
	// An authenticated malformed trailer still consumes the sequence number.
	p.sa.window.commit(p.seq)
	p.plain, p.nextHeader, p.Err = parseTrailer(p.plain)
}

func parseTrailer(plain []byte) ([]byte, byte, error) {
	if len(plain) < 2 {
		return nil, 0, fmt.Errorf("esp: plaintext too short")
	}
	padLen := int(plain[len(plain)-2])
	nextHeader := plain[len(plain)-1]
	if padLen+2 > len(plain) {
		return nil, 0, fmt.Errorf("esp: invalid padding")
	}
	for i, value := range plain[len(plain)-2-padLen : len(plain)-2] {
		if value != byte(i+1) {
			return nil, 0, fmt.Errorf("esp: invalid padding contents")
		}
	}
	return plain[:len(plain)-2-padLen], nextHeader, nil
}

// Plaintext returns the packet only after both authentication and replay commit
// succeeded. An uncommitted or failed result never exposes its plaintext.
func (p *AuthenticatedPacket) Plaintext() ([]byte, byte, error) {
	if p == nil || !p.committed {
		return nil, 0, errUncommitted
	}
	if p.Err != nil {
		return nil, 0, p.Err
	}
	return p.plain, p.nextHeader, nil
}

// Commit checks and advances replay state for a single authenticated packet.
// Ordered receive pipelines use CommitBatch to amortize the same operation.
func (p *AuthenticatedPacket) Commit() ([]byte, byte, error) {
	if p == nil {
		return nil, 0, errUnauthenticated
	}
	if p.sa != nil {
		p.sa.mu.Lock()
	}
	p.commitLocked()
	if p.sa != nil {
		p.sa.mu.Unlock()
	}
	return p.Plaintext()
}

// Open is the single-packet convenience path and preserves the ciphertext.
func (in *InboundSA) Open(pkt []byte) ([]byte, byte, error) {
	authenticated, err := in.Authenticate(pkt)
	if err != nil {
		return nil, 0, err
	}
	return authenticated.Commit()
}
