package esp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"
)

func TestSealBatchReuseAcrossSizesAndSAs(t *testing.T) {
	// Recycle across both batch-size changes and rekeys, including a change
	// of cipher. Check the wire image against the independent single-packet
	// path and decrypt each result before its storage is reused.
	var reuse [][]byte
	for _, suite := range []struct{ id, bits uint16 }{
		{ENCRAESGCM16, 128}, {ENCRAESGCM16, 256}, {ENCRChaCha20Poly1305, 256},
	} {
		t.Run(fmt.Sprintf("%d/%d", suite.id, suite.bits), func(t *testing.T) {
			child := testChild(t)
			child.EncrID, child.EncrKeyBits = suite.id, suite.bits
			child.OutboundKey = bytes.Repeat([]byte{byte(suite.bits)}, int(suite.bits)/8+4)
			child.InboundKey, child.LocalSPI = child.OutboundKey, child.RemoteSPI
			out, err := NewOutbound(child)
			if err != nil {
				t.Fatal(err)
			}
			reference, _ := NewOutbound(child)
			in, _ := NewInbound(child)
			var sequence uint32
			for _, count := range []int{128, 1, 3, 128, 256, 2, 128} {
				plain := make([][]byte, count)
				headers := make([]byte, count)
				for i := range plain {
					plain[i] = bytes.Repeat([]byte{byte(i)}, (i*37+count)%1401)
					headers[i] = NextHeaderIPv4 + byte(i%2)*(NextHeaderIPv6-NextHeaderIPv4)
				}
				r, err := out.ReserveSequenceRange(count)
				if err != nil {
					t.Fatal(err)
				}
				reuse, err = r.SealBatchInto(plain, headers, reuse)
				if err != nil {
					t.Fatal(err)
				}
				for i, packet := range reuse {
					sequence++
					want, err := reference.Seal(plain[i], headers[i])
					if err != nil || !bytes.Equal(packet, want) || binary.BigEndian.Uint32(packet[4:8]) != sequence {
						t.Fatalf("count %d, packet %d differs from single-packet encryption: %v", count, i, err)
					}
					got, nh, err := in.Open(packet)
					if err != nil || nh != headers[i] || !bytes.Equal(got, plain[i]) {
						t.Fatalf("count %d, packet %d failed round trip: %v", count, i, err)
					}
				}
			}
		})
	}
}

func TestSealBatchReuseDoesNotLoseCapacityOrAllocate(t *testing.T) {
	out, _ := NewOutbound(testChild(t))
	plain, headers := benchmarkESPPlaintext(1400)
	var reuse [][]byte
	var first *byte
	allocs := testing.AllocsPerRun(100, func() {
		// Reserve fresh nonces even in this allocation test.
		start, end, err := out.reserveSequenceNumbers(len(plain))
		if err != nil {
			t.Fatal(err)
		}
		r := SequenceRange{sa: out, next: start, end: end}
		reuse, err = r.SealBatchInto(plain, headers, reuse)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = &reuse[0][0]
		} else if first != &reuse[0][0] {
			t.Fatal("recycling a same-size batch lost its original storage")
		}
	})
	if allocs != 0 {
		t.Fatalf("reused encryption allocated %.1f times per batch", allocs)
	}
}
