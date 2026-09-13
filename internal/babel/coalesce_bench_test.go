package babel

import (
	"strconv"
	"testing"
)

func BenchmarkCoalesceOneTarget(b *testing.B) {
	n := &neighborState{}
	for _, k := range []int{100, 1000, 10000} {
		b.Run(strconv.Itoa(k), func(b *testing.B) {
			actions := make([]sendAction, k)
			for i := range actions {
				actions[i] = sendAction{neighbor: n, tlvs: []RawTLV{{Type: TLVSeqnoRequest, Body: make([]byte, 16)}}}
			}
			b.ResetTimer()
			for range b.N {
				coalesce(actions)
			}
		})
	}
}

// Merging must preserve order within a neighbor. A Babel packet carries
// parser state, the router-id and the default prefix, that later TLVs read, so
// reordering them changes what the receiver decodes.
func TestCoalescePreservesOrderWithinNeighbor(t *testing.T) {
	first, second := &neighborState{}, &neighborState{}
	tlv := func(seqno uint16) RawTLV {
		return RawTLV{Type: TLVUpdate, Body: []byte{byte(seqno >> 8), byte(seqno)}}
	}
	actions := []sendAction{
		{neighbor: first, tlvs: []RawTLV{tlv(1)}},
		{neighbor: second, tlvs: []RawTLV{tlv(100)}},
		{neighbor: first, tlvs: []RawTLV{tlv(2), tlv(3)}},
		{neighbor: first, tlvs: []RawTLV{tlv(4)}},
	}
	merged := coalesce(actions)
	if len(merged) != 2 {
		t.Fatalf("coalesced to %d actions, want one per neighbor", len(merged))
	}
	if merged[0].neighbor != first || merged[1].neighbor != second {
		t.Fatal("the neighbors were reordered")
	}
	var seqnos []uint16
	for _, tlv := range merged[0].tlvs {
		seqnos = append(seqnos, uint16(tlv.Body[0])<<8|uint16(tlv.Body[1]))
	}
	if want := []uint16{1, 2, 3, 4}; len(seqnos) != len(want) {
		t.Fatalf("merged %v, want %v", seqnos, want)
	} else {
		for i := range want {
			if seqnos[i] != want[i] {
				t.Fatalf("merged %v, want %v", seqnos, want)
			}
		}
	}
	// The caller's slice must not have been appended into.
	if len(actions[0].tlvs) != 1 {
		t.Errorf("the first action's slice grew to %d, so its backing array was not ours", len(actions[0].tlvs))
	}
}
