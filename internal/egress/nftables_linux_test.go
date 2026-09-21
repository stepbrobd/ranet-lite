//go:build linux && !android

package egress

import (
	"encoding/binary"
	"net/netip"
	"slices"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// expressionNames is the rule's expression list in order, the sequence a
// packet is evaluated against. The encoder is checked against it rather than
// against a byte string, so a test says what the rule does rather than
// restating the encoding.
func expressionNames(t *testing.T, body []byte) []string {
	t.Helper()
	var out []string
	for kind, value := range (nftMessage{Data: body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			for _, field := range nested(element.value) {
				if field.kind == unix.NFTA_EXPR_NAME {
					out = append(out, unix.ByteSliceToString(field.value))
				}
			}
		}
	}
	return out
}

// A rule reaches the kernel as the expressions its comment describes, in the
// order a packet meets them: both interfaces, then the narrowing, then the
// counter, then the translation.
func TestRuleEncodesTheExpressionsItsCommentDescribes(t *testing.T) {
	for _, one := range []struct {
		name string
		rule Rule
		want []string
	}{
		{
			"out of the mesh under the host's own address",
			Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "masq"},
		},
		{
			"out of the mesh under a configured address",
			Rule{Family: FamilyIPv6, Direction: Out, Interface: "ranet0", Source: netip.MustParseAddr("2001:db8::1")},
			[]string{"meta", "cmp", "meta", "cmp", "counter", "immediate", "nat"},
		},
		{
			"into the mesh from one prefix",
			Rule{Family: FamilyIPv4, Direction: In, Interface: "ranet0",
				From: netip.MustParsePrefix("198.51.100.0/24"), Source: netip.MustParseAddr("10.88.0.2")},
			[]string{"meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "counter", "immediate", "nat"},
		},
		{
			"into the mesh from one host",
			Rule{Family: FamilyIPv4, Direction: In, Interface: "ranet0",
				From: netip.MustParsePrefix("198.51.100.7/32"), Source: netip.MustParseAddr("10.88.0.2")},
			// No bitwise: a prefix as long as the address masks nothing.
			[]string{"meta", "cmp", "meta", "cmp", "payload", "cmp", "counter", "immediate", "nat"},
		},
	} {
		t.Run(one.name, func(t *testing.T) {
			request, err := newRule(one.rule)
			if err != nil {
				t.Fatal(err)
			}
			if got := expressionNames(t, request.body); !slices.Equal(got, one.want) {
				t.Errorf("encoded %q, want %q", got, one.want)
			}
			table, chain, spec, _, _ := decodeRule(nftMessage{Data: request.body})
			if table != TableName || chain != ChainName {
				t.Errorf("wrote into %s/%s, want %s/%s", table, chain, TableName, ChainName)
			}
			if spec != one.rule.String() {
				t.Errorf("the rule reads back as %q, want %q, so the diff would rewrite it forever", spec, one.rule.String())
			}
		})
	}
}

// An interface name is compared over the whole IFNAMSIZ the kernel pads it to.
// A shorter comparison matches every device whose name starts the same way, so
// a rule for "ranet0" would also claim traffic on "ranet01".
func TestInterfaceComparisonCoversTheWholePaddedName(t *testing.T) {
	request, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"})
	if err != nil {
		t.Fatal(err)
	}
	found := 0
	for kind, value := range (nftMessage{Data: request.body}).attributes(sizeofNfgenmsg) {
		if kind != unix.NFTA_RULE_EXPRESSIONS {
			continue
		}
		for _, element := range nested(value) {
			var name string
			var data []byte
			for _, field := range nested(element.value) {
				switch field.kind {
				case unix.NFTA_EXPR_NAME:
					name = unix.ByteSliceToString(field.value)
				case unix.NFTA_EXPR_DATA:
					data = field.value
				}
			}
			if name != "cmp" {
				continue
			}
			for _, field := range nested(data) {
				if field.kind != unix.NFTA_CMP_DATA {
					continue
				}
				for _, inner := range nested(field.value) {
					if inner.kind != unix.NFTA_DATA_VALUE {
						continue
					}
					found++
					if len(inner.value) != ifNameSize {
						t.Errorf("compared %d bytes of the name, want %d", len(inner.value), ifNameSize)
					}
					if unix.ByteSliceToString(inner.value) != "ranet0" {
						t.Errorf("compared against %q", inner.value)
					}
				}
			}
		}
	}
	if found != 2 {
		t.Errorf("found %d interface comparisons, want one per direction", found)
	}
}

// The two interface tests carry opposite operators, which is the whole of the
// direction: a rule that compared both the same way would translate mesh
// transit, whose packets arrive on the mesh device and leave by it again.
func TestDirectionInvertsBothInterfaceTests(t *testing.T) {
	for _, one := range []struct {
		direction Direction
		want      []uint32
	}{
		{Out, []uint32{unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ}},
		{In, []uint32{unix.NFT_CMP_NEQ, unix.NFT_CMP_EQ}},
	} {
		t.Run(one.direction.String(), func(t *testing.T) {
			request, err := newRule(Rule{Family: FamilyIPv4, Direction: one.direction, Interface: "ranet0"})
			if err != nil {
				t.Fatal(err)
			}
			var got []uint32
			for kind, value := range (nftMessage{Data: request.body}).attributes(sizeofNfgenmsg) {
				if kind != unix.NFTA_RULE_EXPRESSIONS {
					continue
				}
				for _, element := range nested(value) {
					var name string
					var data []byte
					for _, field := range nested(element.value) {
						switch field.kind {
						case unix.NFTA_EXPR_NAME:
							name = unix.ByteSliceToString(field.value)
						case unix.NFTA_EXPR_DATA:
							data = field.value
						}
					}
					if name != "cmp" {
						continue
					}
					for _, field := range nested(data) {
						if field.kind == unix.NFTA_CMP_OP && len(field.value) == 4 {
							got = append(got, binary.BigEndian.Uint32(field.value))
						}
					}
				}
			}
			if !slices.Equal(got, one.want) {
				t.Errorf("compared with %v, want %v", got, one.want)
			}
		})
	}
}

// A prefix narrows a rule by the bits it actually covers, so a /24 masks the
// last octet away and a /0 is never encoded at all.
func TestPrefixMaskCoversExactlyThePrefixLength(t *testing.T) {
	for _, one := range []struct {
		prefix string
		want   []byte
	}{
		{"198.51.100.0/24", []byte{0xff, 0xff, 0xff, 0x00}},
		{"198.51.100.0/22", []byte{0xff, 0xff, 0xfc, 0x00}},
		{"198.51.100.7/32", []byte{0xff, 0xff, 0xff, 0xff}},
		{"0.0.0.0/0", []byte{0x00, 0x00, 0x00, 0x00}},
	} {
		t.Run(one.prefix, func(t *testing.T) {
			if got := prefixMask(netip.MustParsePrefix(one.prefix)); !slices.Equal(got, one.want) {
				t.Errorf("masked with %x, want %x", got, one.want)
			}
		})
	}
	if got := prefixMask(netip.MustParsePrefix("2001:db8::/48")); len(got) != ipv6AddressLen {
		t.Errorf("an IPv6 mask is %d bytes, want %d", len(got), ipv6AddressLen)
	}
}

// A rule's identity travels in its own comment, so the diff reads back the
// spelling it wrote rather than re-deriving it from the expressions.
func TestCommentRoundTripsThroughUserdata(t *testing.T) {
	spec := Rule{Family: FamilyIPv4, Direction: Out, Interface: "ranet0"}.String()
	if got := comment(userdata(spec)); got != spec {
		t.Errorf("read back %q, want %q", got, spec)
	}
	// Another writer's userdata comes first in the same blob. Skipping it by
	// its length rather than assuming the comment is first is the difference
	// between a rule this package recognizes and one it reinstalls forever.
	blob := append([]byte{7, 3, 'a', 'b', 'c'}, userdata(spec)...)
	if got := comment(blob); got != spec {
		t.Errorf("read back %q past another writer's entry, want %q", got, spec)
	}
	if got := comment([]byte{0, 9, 'a'}); got != "" {
		t.Errorf("a truncated entry read as %q", got)
	}
}

// A rule the kernel hands back carries its counter in the expression list, and
// the counter is of flows rather than of packets: a nat chain is consulted
// once per connection and never again.
func TestCountersComeOutOfTheExpressionList(t *testing.T) {
	var counter []byte
	counter = putAttr(counter, unix.NFTA_COUNTER_BYTES, beBytes(4242))
	counter = putAttr(counter, unix.NFTA_COUNTER_PACKETS, beBytes(17))
	expressions := slices.Concat(expression("meta", nil), expression("counter", counter))
	packets, bytes := counters(expressions)
	if packets != 17 || bytes != 4242 {
		t.Errorf("read %d flows and %d bytes, want 17 and 4242", packets, bytes)
	}
}

func beBytes(value uint64) []byte {
	var raw [8]byte
	binary.BigEndian.PutUint64(raw[:], value)
	return raw[:]
}

// A comment longer than the host will hold is refused rather than truncated,
// because a truncated comment is a rule this package no longer recognizes and
// would replace on every pass for the life of the node.
func TestRuleWithAnOversizedCommentIsRefused(t *testing.T) {
	long := strings.Repeat("x", udataCommentMax)
	_, err := newRule(Rule{Family: FamilyIPv4, Direction: Out, Interface: long})
	if err == nil || !strings.Contains(err.Error(), "comment") {
		t.Fatalf("refused with %v, want a message naming the limit", err)
	}
}

// A datagram whose message claims to run past its end is an error rather than
// a short read, so a truncated dump can never look like a complete one and a
// diff built on it can never withdraw a rule that is still there.
func TestMalformedMessageLengthIsRefused(t *testing.T) {
	buf := make([]byte, unix.SizeofNlMsghdr)
	binary.NativeEndian.PutUint32(buf, uint32(len(buf)+64))
	if _, err := parseMessages(buf); err == nil {
		t.Fatal("a message running past its datagram was accepted")
	}
}

// The chain is a nat base chain at the source translation hook, which is where
// every other source translation on the host runs too. A number nothing else
// uses would not avoid the overlap, only decide whether this node translates
// before or after whatever the operator arranged on purpose.
func TestChainIsNatAtTheSourceTranslationHook(t *testing.T) {
	request := newChain(FamilyIPv4)
	table, chain, kind, hook, priority := decodeChain(nftMessage{Data: request.body})
	if table != TableName || chain != ChainName {
		t.Errorf("created %s/%s, want %s/%s", table, chain, TableName, ChainName)
	}
	if kind != "nat" {
		t.Errorf("created a %q chain, want nat", kind)
	}
	if hook != unix.NF_INET_POST_ROUTING {
		t.Errorf("hooked at %d, want postrouting (%d)", hook, unix.NF_INET_POST_ROUTING)
	}
	if priority != natSrcPriority {
		t.Errorf("hooked at priority %d, want %d", priority, natSrcPriority)
	}
}

// Emptying the chain names a table and a chain and no handle, which nf_tables
// reads as every rule in that chain. It can reach no other table, which is the
// ownership claim this package makes.
func TestFlushNamesOnlyThisToolsOwnChain(t *testing.T) {
	request := flushChain(FamilyIPv6)
	var table, chain string
	handles := 0
	for kind, value := range (nftMessage{Data: request.body}).attributes(sizeofNfgenmsg) {
		switch kind {
		case unix.NFTA_RULE_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_CHAIN:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_HANDLE:
			handles++
		}
	}
	if table != TableName || chain != ChainName {
		t.Errorf("would empty %s/%s, want %s/%s", table, chain, TableName, ChainName)
	}
	if handles != 0 {
		t.Errorf("named %d handles, which would delete one rule rather than the chain", handles)
	}
}
