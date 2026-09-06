package esp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand/v2"
	"sync"
	"testing"
)

func TestBatchMatchesSinglePacketReplayChecks(t *testing.T) {
	for _, window := range []uint32{0, 1, 64, 4096} {
		t.Run(fmt.Sprintf("window=%d", window), func(t *testing.T) {
			child := testChild(t)
			child.LocalSPI, child.InboundKey = child.RemoteSPI, child.OutboundKey
			out, _ := NewOutbound(child)
			single, _ := NewInbound(child, WithReplayWindow(window))
			batch, _ := NewInbound(child, WithReplayWindow(window))
			wire := make([][]byte, 256)
			for i := range wire {
				var err error
				wire[i], err = out.Seal([]byte{byte(i)}, NextHeaderIPv4)
				if err != nil {
					t.Fatal(err)
				}
			}
			rng := rand.New(rand.NewPCG(17, 23))
			var results []AuthenticatedPacket
			for round := range 40 {
				packets := make([][]byte, 32)
				for i := range packets {
					packets[i] = bytes.Clone(wire[rng.IntN(len(wire))])
					switch rng.IntN(8) {
					case 0:
						packets[i][len(packets[i])-1] ^= 1 // bad tag
					case 1:
						packets[i] = packets[i][:3] // truncated header
					case 2:
						packets[i][0] ^= 1 // wrong SPI
					}
				}
				want := make([][]byte, len(packets))
				accepted := make([]bool, len(packets))
				for i, packet := range packets {
					plain, _, err := single.Open(packet)
					want[i], accepted[i] = plain, err == nil
				}
				results = batch.AuthenticateBatchInPlace(packets, results[:0])
				for i := range results {
					if plain, _, err := results[i].Plaintext(); plain != nil || err == nil {
						t.Fatal("plaintext exposed before replay commit")
					}
				}
				CommitBatch(results)
				for i := range results {
					plain, nh, err := results[i].Plaintext()
					if (err == nil) != accepted[i] || !bytes.Equal(plain, want[i]) || (err == nil && nh != NextHeaderIPv4) {
						t.Fatalf("round %d packet %d: batch (%x, %d, %v), single (%x, accepted=%v)", round, i, plain, nh, err, want[i], accepted[i])
					}
				}
			}
		})
	}
}

func TestBatchCommitRechecksConcurrentDuplicates(t *testing.T) {
	child := testChild(t)
	child.LocalSPI, child.InboundKey = child.RemoteSPI, child.OutboundKey
	out, _ := NewOutbound(child)
	in, _ := NewInbound(child)
	const count = 128
	packets := make([][]byte, count)
	for i := range packets {
		packets[i], _ = out.Seal([]byte{byte(i)}, NextHeaderIPv4)
	}
	var batches [4][]AuthenticatedPacket
	var wg sync.WaitGroup
	for worker := range batches {
		wg.Go(func() {
			owned := make([][]byte, len(packets))
			for i := range owned {
				owned[i] = bytes.Clone(packets[i])
			}
			batches[worker] = in.AuthenticateBatchInPlace(owned, nil)
		})
	}
	wg.Wait()
	for _, batch := range batches {
		wg.Go(func() { CommitBatch(batch) })
	}
	wg.Wait()
	for i := range packets {
		accepted := 0
		for _, batch := range batches {
			if _, _, err := batch[i].Plaintext(); err == nil {
				accepted++
			}
		}
		if accepted != 1 {
			t.Fatalf("packet %d accepted %d times, want exactly once", i, accepted)
		}
	}
}

func TestBatchMalformedAuthenticatedTrailerStillConsumesSequence(t *testing.T) {
	child := testChild(t)
	child.LocalSPI, child.InboundKey = child.RemoteSPI, child.OutboundKey
	out, _ := NewOutbound(child)
	in, _ := NewInbound(child)
	duplicate, _ := out.Seal([]byte("duplicate"), NextHeaderIPv4)
	next, _ := out.Seal([]byte("next"), NextHeaderIPv4)
	malformed := make([]byte, headerLen+out.params.IVLen)
	binary.BigEndian.PutUint32(malformed, child.LocalSPI)
	binary.BigEndian.PutUint32(malformed[4:], 1)
	binary.BigEndian.PutUint64(malformed[8:], 1)
	nonce := append(bytes.Clone(out.salt), malformed[8:16]...)
	malformed = out.aead.Seal(malformed, nonce, []byte{0, 3, NextHeaderIPv4}, malformed[:headerLen])
	results := in.AuthenticateBatchInPlace([][]byte{malformed, duplicate, next}, nil)
	for _, result := range results {
		if result.Err != nil {
			t.Fatalf("valid AEAD tag rejected before trailer/replay commit: %v", result.Err)
		}
	}
	CommitBatch(results)
	for i := range 2 {
		if plain, _, err := results[i].Plaintext(); plain != nil || err == nil {
			t.Fatalf("accepted malformed trailer or its repeated sequence at index %d", i)
		}
	}
	if plain, _, err := results[2].Plaintext(); err != nil || string(plain) != "next" {
		t.Fatalf("valid next packet rejected: %q, %v", plain, err)
	}
}

func TestCommitBatchSpansSAsAndRejectsZeroResults(t *testing.T) {
	var results []AuthenticatedPacket
	for _, spi := range []uint32{1, 2, 1} {
		child := testChild(t)
		child.LocalSPI, child.RemoteSPI, child.InboundKey = spi, spi, child.OutboundKey
		out, _ := NewOutbound(child)
		in, _ := NewInbound(child)
		packet, _ := out.Seal([]byte{byte(spi)}, NextHeaderIPv6)
		results = in.AuthenticateBatchInPlace([][]byte{packet}, results)
		results = append(results, AuthenticatedPacket{})
	}
	CommitBatch(results)
	for i := range results {
		plain, nh, err := results[i].Plaintext()
		if i%2 == 1 {
			if err == nil || plain != nil {
				t.Fatal("zero result exposed plaintext")
			}
		} else if err != nil || len(plain) != 1 || nh != NextHeaderIPv6 {
			t.Fatalf("valid result lost across an SA boundary: %v", err)
		}
	}
	CommitBatch(results)
	for i := range results {
		if _, _, err := results[i].Plaintext(); err == nil {
			t.Fatal("same result committed twice")
		}
	}
}
