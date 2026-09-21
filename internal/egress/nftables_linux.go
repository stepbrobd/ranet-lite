//go:build linux && !android

package egress

import (
	"encoding/binary"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strings"

	"golang.org/x/sys/unix"
)

// This file speaks nf_tables over NETLINK_NETFILTER directly, the way
// internal/kernel speaks rtnetlink: no `nft` to shell out to, no library to
// add, and the same request and reply discipline on one socket used by one
// goroutine.
//
// Two things about nf_tables differ from rtnetlink and both are used here.
// Every integer in an NFTA_ attribute is big endian, header fields included,
// while the netlink header itself stays native. And every write is a
// transaction: a batch between NFNL_MSG_BATCH_BEGIN and NFNL_MSG_BATCH_END
// commits whole or not at all, which is how a chain is replaced with no window
// in which a packet leaves untranslated.

const (
	// sizeofNfgenmsg is struct nfgenmsg: family, version and a big-endian
	// res_id. Named here rather than taken from x/sys, which does not carry it.
	sizeofNfgenmsg = 4
	// nfnetlinkV0 is NFNETLINK_V0, the only version there is.
	nfnetlinkV0 = 0
	// natSrcPriority is NF_IP_PRI_NAT_SRC, where source translation runs.
	// Chains of several writers coexist there; see Conflicts.
	natSrcPriority = 100
	// chainAccept is NF_ACCEPT, the only policy a nat base chain may carry
	// here: this package translates and never decides whether a packet lives.
	chainAccept = 1
	// nlaNested and nlaTypeMask are NLA_F_NESTED and NLA_TYPE_MASK. libnftnl
	// sets the flag, so it is set on the way out and masked off on the way in.
	nlaNested   = 0x8000
	nlaTypeMask = 0x3fff
	// udataComment is NFTNL_UDATA_RULE_COMMENT, the userdata type `nft` prints
	// as a rule's comment. This package writes Rule.String there and diffs on
	// it, so a rule reads in `nft list ruleset` exactly as the diff key spells
	// it.
	udataComment = 0
	// udataCommentMax is the comment length nft itself accepts.
	udataCommentMax = 128
	// ifNameSize is IFNAMSIZ. meta iifname and oifname load a NUL-padded name
	// of exactly this width, so a comparison has to be the same width or it
	// matches a prefix of another device's name.
	ifNameSize = 16
	// ipv4SourceOffset and ipv6SourceOffset are where the source address sits
	// in each network header, with the length that follows it.
	ipv4SourceOffset, ipv4AddressLen = 12, 4
	ipv6SourceOffset, ipv6AddressLen = 8, 16
)

// nftables is the linux backend: the tables named after this tool, one per
// address family in use.
type nftables struct {
	conn     *nftConn
	families []uint8
}

func newBackend(cfg Config, _ Runtime) (backend, error) {
	conn, err := dialNetfilter()
	if err != nil {
		return nil, err
	}
	be := &nftables{conn: conn, families: cfg.families()}
	// A table this tool left behind in a family the configuration no longer
	// covers would go on translating under the old rules for as long as the
	// node ran, and nothing else here would ever look at it: every dump below
	// asks only about the families in use. It is removed once, at startup,
	// which is the only moment the set can have changed.
	if err := be.removeUnusedTables(); err != nil {
		conn.Close()
		return nil, err
	}
	return be, nil
}

func (n *nftables) Close() error { return n.conn.Close() }

// where names the tables this backend owns, for a log line.
func (n *nftables) where(Config) string {
	names := make([]string, 0, len(n.families))
	for _, family := range n.families {
		names = append(names, tableFamilyName(family))
	}
	return fmt.Sprintf("nftables table %s %s chain %s", strings.Join(names, " and "), TableName, ChainName)
}

// tableFamilyName is the family as `nft` spells it. The two are separate
// tables rather than one inet table because inet nat arrived long after
// nftables did, and a node whose kernel predates it would refuse the chain
// rather than the capability.
func tableFamilyName(family uint8) string {
	if family == FamilyIPv4 {
		return "ip"
	}
	return "ip6"
}

// nftFamily is the NFPROTO_ value for one of this package's families.
func nftFamily(family uint8) uint8 {
	if family == FamilyIPv4 {
		return unix.NFPROTO_IPV4
	}
	return unix.NFPROTO_IPV6
}

// Rules reads back the chain this tool owns, in order, with the flow counter
// each rule has carried. Only the table named after this tool is read, so a
// dump can never return somebody else's rule and a diff built on it can never
// remove one.
func (n *nftables) Rules() ([]Installed, error) {
	var out []Installed
	for _, family := range n.families {
		body := putNfgenmsg(nil, nftFamily(family))
		replies, err := n.conn.dump(nftCommand(unix.NFT_MSG_GETRULE), body)
		if err != nil {
			return nil, fmt.Errorf("egress: dump %s rules: %w", tableFamilyName(family), err)
		}
		for _, reply := range replies {
			table, chain, spec, packets, bytes := decodeRule(reply)
			if table != TableName || chain != ChainName || spec == "" {
				continue
			}
			out = append(out, Installed{Spec: spec, Packets: packets, Bytes: bytes})
		}
	}
	return out, nil
}

// decodeRule reads the fields a diff and a report need: where the rule lives,
// the comment this package wrote as its identity, and the counter. The
// expressions are walked only far enough to find that counter, because the
// comment already says what the rule does and re-deriving it from the
// expressions would be a second encoder to keep in step with the first.
func decodeRule(message nftMessage) (table, chain, spec string, packets, bytes uint64) {
	for kind, value := range message.attributes(sizeofNfgenmsg) {
		switch kind {
		case unix.NFTA_RULE_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_CHAIN:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_RULE_USERDATA:
			spec = comment(value)
		case unix.NFTA_RULE_EXPRESSIONS:
			packets, bytes = counters(value)
		}
	}
	return table, chain, spec, packets, bytes
}

// comment is the rule's identity as this package wrote it, out of the
// libnftnl userdata format: a sequence of type, length and value triples, of
// which this package writes exactly one.
func comment(userdata []byte) string {
	for len(userdata) >= 2 {
		kind, length := userdata[0], int(userdata[1])
		if len(userdata) < 2+length {
			return ""
		}
		if kind == udataComment {
			return strings.TrimRight(string(userdata[2:2+length]), "\x00")
		}
		userdata = userdata[2+length:]
	}
	return ""
}

// counters walks the expression list for the counter this package puts in
// every rule. The count is of flows rather than of packets: a nat chain is
// evaluated once per connection, when conntrack first sees it, and every
// packet after that is translated without the chain being consulted.
func counters(expressions []byte) (packets, bytes uint64) {
	for _, element := range nested(expressions) {
		if element.kind != unix.NFTA_LIST_ELEM {
			continue
		}
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
		if name != "counter" {
			continue
		}
		for _, field := range nested(data) {
			if len(field.value) != 8 {
				continue
			}
			switch field.kind {
			case unix.NFTA_COUNTER_BYTES:
				bytes = binary.BigEndian.Uint64(field.value)
			case unix.NFTA_COUNTER_PACKETS:
				packets = binary.BigEndian.Uint64(field.value)
			}
		}
	}
	return packets, bytes
}

// Apply brings this tool's own chain to rules, in one transaction. The chain
// is emptied and rewritten rather than edited rule by rule, because a batch
// commits atomically: no packet is ever evaluated against half a ruleset, and
// the alternative is a window in which a flow leaves untranslated and
// conntrack then holds that decision for its whole lifetime.
func (n *nftables) Apply(rules []Rule) error {
	var requests []nftRequest
	for _, family := range n.families {
		requests = append(requests,
			newTable(family),
			newChain(family),
			// No handle, which is how nf_tables spells "every rule in this
			// chain". It reaches only the chain named here, in the table named
			// here, both of which this tool created.
			flushChain(family))
		for _, rule := range rules {
			if rule.Family != family {
				continue
			}
			request, err := newRule(rule)
			if err != nil {
				return err
			}
			requests = append(requests, request)
		}
	}
	return n.conn.batch(requests)
}

// Withdraw removes the tables this tool created, and only those: the dump
// names them, and a name that is not this tool's is never deleted. Both
// families are swept rather than the configured ones alone, so a table left
// behind by an instance with a different configuration leaves with the rest.
func (n *nftables) Withdraw() error {
	return n.removeTables(func(uint8) bool { return true })
}

// removeUnusedTables is Withdraw narrowed to the families this configuration
// does not cover. See newBackend.
func (n *nftables) removeUnusedTables() error {
	return n.removeTables(func(family uint8) bool { return !slices.Contains(n.families, family) })
}

// removeTables deletes this tool's table in each family the predicate takes.
// The tables are listed first rather than deleted blind, because a delete of a
// table that is not there fails the whole transaction and would turn every
// shutdown on a node that never installed anything into an error.
func (n *nftables) removeTables(match func(uint8) bool) error {
	held, err := n.ownTables()
	if err != nil {
		return err
	}
	var requests []nftRequest
	for _, family := range held {
		if match(family) {
			requests = append(requests, delTable(family))
		}
	}
	return n.conn.batch(requests)
}

// ownTables is the families in which a table of this tool's name exists.
func (n *nftables) ownTables() ([]uint8, error) {
	replies, err := n.conn.dump(nftCommand(unix.NFT_MSG_GETTABLE), putNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("egress: dump tables: %w", err)
	}
	var out []uint8
	for _, reply := range replies {
		if len(reply.Data) < sizeofNfgenmsg {
			continue
		}
		var family uint8
		switch reply.Data[0] {
		case unix.NFPROTO_IPV4:
			family = FamilyIPv4
		case unix.NFPROTO_IPV6:
			family = FamilyIPv6
		default:
			continue
		}
		for kind, value := range reply.attributes(sizeofNfgenmsg) {
			if kind == unix.NFTA_TABLE_NAME && unix.ByteSliceToString(value) == TableName &&
				!slices.Contains(out, family) {
				out = append(out, family)
			}
		}
	}
	slices.Sort(out)
	return out, nil
}

// Conflicts names the other source translation this node's traffic can meet: a
// nat chain at the postrouting hook in a table this tool did not create. They
// are reported rather than removed. Several such chains coexist, the first to
// translate a connection keeps it, and a tool that deleted its neighbours'
// rules to win that race would break docker, an SD-WAN agent or the operator's
// own ruleset, which is exactly the failure internal/kernel's ownership rules
// exist to avoid.
//
// A host still running legacy iptables rather than iptables-nft is invisible
// here, because the two are separate registries in the kernel. An iptables-nft
// rule is an ordinary nftables table and does show up.
func (n *nftables) Conflicts() ([]string, error) {
	replies, err := n.conn.dump(nftCommand(unix.NFT_MSG_GETCHAIN), putNfgenmsg(nil, unix.NFPROTO_UNSPEC))
	if err != nil {
		return nil, fmt.Errorf("egress: dump chains: %w", err)
	}
	var out []string
	for _, reply := range replies {
		if len(reply.Data) < sizeofNfgenmsg {
			continue
		}
		var family uint8
		switch reply.Data[0] {
		case unix.NFPROTO_IPV4:
			family = FamilyIPv4
		case unix.NFPROTO_IPV6:
			family = FamilyIPv6
		default:
			// An inet, bridge, arp or netdev chain cannot carry a nat hook
			// this node's forwarded traffic would meet before its own.
			continue
		}
		if !slices.Contains(n.families, family) {
			continue
		}
		table, chain, kind, hook, priority := decodeChain(reply)
		if table == TableName || kind != "nat" || hook != unix.NF_INET_POST_ROUTING {
			continue
		}
		out = append(out, fmt.Sprintf("%s table %s chain %s at priority %d",
			tableFamilyName(family), table, chain, priority))
	}
	slices.Sort(out)
	return out, nil
}

func decodeChain(message nftMessage) (table, chain, kind string, hook uint32, priority int32) {
	// A chain with no hook is a regular chain, reached by a jump rather than
	// by the packet path, so the absent hook is reported as one no packet
	// enters at.
	hook = ^uint32(0)
	for attribute, value := range message.attributes(sizeofNfgenmsg) {
		switch attribute {
		case unix.NFTA_CHAIN_TABLE:
			table = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_NAME:
			chain = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_TYPE:
			kind = unix.ByteSliceToString(value)
		case unix.NFTA_CHAIN_HOOK:
			for _, field := range nested(value) {
				if len(field.value) != 4 {
					continue
				}
				switch field.kind {
				case unix.NFTA_HOOK_HOOKNUM:
					hook = binary.BigEndian.Uint32(field.value)
				case unix.NFTA_HOOK_PRIORITY:
					priority = int32(binary.BigEndian.Uint32(field.value))
				}
			}
		}
	}
	return table, chain, kind, hook, priority
}

// newTable creates the table if it is absent and leaves it alone if it is
// there, which is how a table a previous instance left behind is adopted.
func newTable(family uint8) nftRequest {
	body := putNfgenmsg(nil, nftFamily(family))
	body = putAttrString(body, unix.NFTA_TABLE_NAME, TableName)
	return nftRequest{kind: nftCommand(unix.NFT_MSG_NEWTABLE), flags: unix.NLM_F_CREATE, body: body}
}

func delTable(family uint8) nftRequest {
	body := putNfgenmsg(nil, nftFamily(family))
	body = putAttrString(body, unix.NFTA_TABLE_NAME, TableName)
	return nftRequest{kind: nftCommand(unix.NFT_MSG_DELTABLE), body: body}
}

// newChain creates the one base chain, at the source translation hook and the
// priority every other source translation on the host also runs at. A
// different priority would not avoid the overlap, only reorder it, and a
// number nothing else uses would put this node's translation either before or
// after whatever the operator arranged on purpose.
func newChain(family uint8) nftRequest {
	hook := putAttrBE32(nil, unix.NFTA_HOOK_HOOKNUM, unix.NF_INET_POST_ROUTING)
	hook = putAttrBE32(hook, unix.NFTA_HOOK_PRIORITY, uint32(natSrcPriority))
	body := putNfgenmsg(nil, nftFamily(family))
	body = putAttrString(body, unix.NFTA_CHAIN_TABLE, TableName)
	body = putAttrString(body, unix.NFTA_CHAIN_NAME, ChainName)
	body = putAttr(body, unix.NFTA_CHAIN_HOOK|nlaNested, hook)
	body = putAttrBE32(body, unix.NFTA_CHAIN_POLICY, chainAccept)
	body = putAttrString(body, unix.NFTA_CHAIN_TYPE, "nat")
	return nftRequest{kind: nftCommand(unix.NFT_MSG_NEWCHAIN), flags: unix.NLM_F_CREATE, body: body}
}

// flushChain empties the chain. It names a table and a chain and no handle,
// which nf_tables reads as every rule in that chain.
func flushChain(family uint8) nftRequest {
	body := putNfgenmsg(nil, nftFamily(family))
	body = putAttrString(body, unix.NFTA_RULE_TABLE, TableName)
	body = putAttrString(body, unix.NFTA_RULE_CHAIN, ChainName)
	return nftRequest{kind: nftCommand(unix.NFT_MSG_DELRULE), body: body}
}

// newRule encodes one translation. The expressions read as the rule does in
// `nft list ruleset`: match the direction by interface, narrow an inbound rule
// to the prefix it was written for, count, and translate.
func newRule(rule Rule) (nftRequest, error) {
	spec := rule.String()
	if len(spec) >= udataCommentMax {
		return nftRequest{}, fmt.Errorf("egress: rule %s does not fit in a %d byte comment, which is its identity on the host", spec, udataCommentMax)
	}
	inbound, outbound := unix.NFT_CMP_EQ, unix.NFT_CMP_NEQ
	if rule.Direction == In {
		inbound, outbound = unix.NFT_CMP_NEQ, unix.NFT_CMP_EQ
	}
	// Both interfaces are matched, never one. An outbound rule that checked
	// only the arrival interface would also translate mesh transit, which
	// arrives on the mesh device and leaves by it again, and would rewrite a
	// relayed packet's source to this node.
	//
	// A packet this host generated itself has no arrival interface at all, and
	// nf_tables breaks out of a rule whose meta iifname cannot be read, so
	// neither spelling of the interface test ever reaches one.
	expressions := metaCompare(unix.NFT_META_IIFNAME, inbound, rule.Interface)
	expressions = append(expressions, metaCompare(unix.NFT_META_OIFNAME, outbound, rule.Interface)...)
	if rule.From.IsValid() {
		expressions = append(expressions, sourcePrefix(rule.From)...)
	}
	expressions = append(expressions, expression("counter", nil))
	expressions = append(expressions, translate(rule)...)

	body := putNfgenmsg(nil, nftFamily(rule.Family))
	body = putAttrString(body, unix.NFTA_RULE_TABLE, TableName)
	body = putAttrString(body, unix.NFTA_RULE_CHAIN, ChainName)
	body = putAttr(body, unix.NFTA_RULE_EXPRESSIONS|nlaNested, slices.Concat(expressions...))
	body = putAttr(body, unix.NFTA_RULE_USERDATA, userdata(spec))
	return nftRequest{kind: nftCommand(unix.NFT_MSG_NEWRULE), flags: unix.NLM_F_CREATE | unix.NLM_F_APPEND, body: body}, nil
}

// translate is the statement that rewrites the source: the address written in
// the configuration, or the one the host's own routes would have used, which
// nf_tables spells as masquerade and decides per packet.
func translate(rule Rule) [][]byte {
	if !rule.Source.IsValid() {
		return [][]byte{expression("masq", nil)}
	}
	immediate := putAttrBE32(nil, unix.NFTA_IMMEDIATE_DREG, unix.NFT_REG_1)
	immediate = putAttr(immediate, unix.NFTA_IMMEDIATE_DATA|nlaNested,
		putAttr(nil, unix.NFTA_DATA_VALUE, addressBytes(rule.Source)))
	nat := putAttrBE32(nil, unix.NFTA_NAT_TYPE, unix.NFT_NAT_SNAT)
	nat = putAttrBE32(nat, unix.NFTA_NAT_FAMILY, uint32(nftFamily(rule.Family)))
	nat = putAttrBE32(nat, unix.NFTA_NAT_REG_ADDR_MIN, unix.NFT_REG_1)
	return [][]byte{expression("immediate", immediate), expression("nat", nat)}
}

// metaCompare loads one interface name and compares it, over the full
// IFNAMSIZ the kernel pads it to. A shorter comparison would match every
// device whose name starts the same way.
func metaCompare(key uint32, op int, name string) [][]byte {
	meta := putAttrBE32(nil, unix.NFTA_META_KEY, key)
	meta = putAttrBE32(meta, unix.NFTA_META_DREG, unix.NFT_REG_1)
	padded := make([]byte, ifNameSize)
	copy(padded, name)
	return [][]byte{expression("meta", meta), expression("cmp", compare(op, padded))}
}

// sourcePrefix narrows a rule to packets sourced from one prefix: load the
// source out of the network header, mask it where the prefix is shorter than
// the address, and compare.
func sourcePrefix(prefix netip.Prefix) [][]byte {
	offset, length := uint32(ipv6SourceOffset), uint32(ipv6AddressLen)
	if prefix.Addr().Is4() {
		offset, length = ipv4SourceOffset, ipv4AddressLen
	}
	load := putAttrBE32(nil, unix.NFTA_PAYLOAD_DREG, unix.NFT_REG_1)
	load = putAttrBE32(load, unix.NFTA_PAYLOAD_BASE, unix.NFT_PAYLOAD_NETWORK_HEADER)
	load = putAttrBE32(load, unix.NFTA_PAYLOAD_OFFSET, offset)
	load = putAttrBE32(load, unix.NFTA_PAYLOAD_LEN, length)
	out := [][]byte{expression("payload", load)}
	if int(prefix.Bits()) < int(length)*8 {
		mask := prefixMask(prefix)
		bitwise := putAttrBE32(nil, unix.NFTA_BITWISE_SREG, unix.NFT_REG_1)
		bitwise = putAttrBE32(bitwise, unix.NFTA_BITWISE_DREG, unix.NFT_REG_1)
		bitwise = putAttrBE32(bitwise, unix.NFTA_BITWISE_LEN, length)
		bitwise = putAttr(bitwise, unix.NFTA_BITWISE_MASK|nlaNested, putAttr(nil, unix.NFTA_DATA_VALUE, mask))
		bitwise = putAttr(bitwise, unix.NFTA_BITWISE_XOR|nlaNested,
			putAttr(nil, unix.NFTA_DATA_VALUE, make([]byte, length)))
		out = append(out, expression("bitwise", bitwise))
	}
	return append(out, expression("cmp", compare(unix.NFT_CMP_EQ, addressBytes(prefix.Masked().Addr()))))
}

// prefixMask is the prefix length as the bytes a bitwise expression masks
// with.
func prefixMask(prefix netip.Prefix) []byte {
	length := ipv6AddressLen
	if prefix.Addr().Is4() {
		length = ipv4AddressLen
	}
	mask := make([]byte, length)
	bits := prefix.Bits()
	for i := range mask {
		switch {
		case bits >= 8:
			mask[i] = 0xff
			bits -= 8
		case bits > 0:
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return mask
}

func compare(op int, value []byte) []byte {
	body := putAttrBE32(nil, unix.NFTA_CMP_SREG, unix.NFT_REG_1)
	body = putAttrBE32(body, unix.NFTA_CMP_OP, uint32(op))
	return putAttr(body, unix.NFTA_CMP_DATA|nlaNested, putAttr(nil, unix.NFTA_DATA_VALUE, value))
}

// expression is one element of a rule's expression list: a name and the
// attributes that expression takes. The data attribute is emitted even when
// empty, as libnftnl emits it, so an expression carrying no parameters still
// reads as one.
func expression(name string, data []byte) []byte {
	body := putAttrString(nil, unix.NFTA_EXPR_NAME, name)
	body = putAttr(body, unix.NFTA_EXPR_DATA|nlaNested, data)
	return putAttr(nil, unix.NFTA_LIST_ELEM|nlaNested, body)
}

// userdata is the comment in the format libnftnl reads, so `nft list ruleset`
// prints this package's own spelling of the rule beside it.
func userdata(spec string) []byte {
	value := append([]byte(spec), 0)
	return append([]byte{udataComment, byte(len(value))}, value...)
}

// addressBytes is the wire form of an address, four bytes or sixteen, never
// the 4-in-6 form: a table is per family here, so the family is already
// decided by the time an address is encoded.
func addressBytes(address netip.Addr) []byte {
	if address.Is4() {
		raw := address.As4()
		return raw[:]
	}
	raw := address.As16()
	return raw[:]
}

// nftConn is one NETLINK_NETFILTER socket used for synchronous request and
// reply. The single reconcile goroutine is its only caller, so it needs no
// locking, and nothing subscribes to a notification group, so an unsolicited
// message can never arrive on it.
type nftConn struct {
	fd  int
	pid uint32
	seq uint32
	buf []byte
}

// replyTimeout bounds a wait on the kernel. A batch is acknowledged message by
// message and a dump ends at NLMSG_DONE, so a reply that never comes is a
// kernel that did not understand the request, and blocking on it forever would
// stop the reconcile loop with no error to report.
const replyTimeout = 10

func dialNetfilter() (*nftConn, error) {
	fd, err := unix.Socket(unix.AF_NETLINK, unix.SOCK_RAW|unix.SOCK_CLOEXEC, unix.NETLINK_NETFILTER)
	if err != nil {
		return nil, fmt.Errorf("egress: open netfilter netlink socket: %w", err)
	}
	if err := unix.Bind(fd, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: bind netfilter netlink socket: %w", err)
	}
	name, err := unix.Getsockname(fd)
	if err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: read netfilter netlink socket name: %w", err)
	}
	local, ok := name.(*unix.SockaddrNetlink)
	if !ok {
		_ = unix.Close(fd)
		return nil, errors.New("egress: netfilter socket is not a netlink socket")
	}
	timeout := unix.Timeval{Sec: replyTimeout}
	if err := unix.SetsockoptTimeval(fd, unix.SOL_SOCKET, unix.SO_RCVTIMEO, &timeout); err != nil {
		_ = unix.Close(fd)
		return nil, fmt.Errorf("egress: set netfilter netlink receive timeout: %w", err)
	}
	return &nftConn{fd: fd, pid: local.Pid, buf: make([]byte, 64*1024)}, nil
}

func (c *nftConn) Close() error { return unix.Close(c.fd) }

// nftRequest is one message inside a transaction.
type nftRequest struct {
	kind  uint16
	flags uint16
	body  []byte
}

// nftCommand is the netlink message type for one nf_tables command.
func nftCommand(command int) uint16 {
	return uint16(unix.NFNL_SUBSYS_NFTABLES)<<8 | uint16(command)
}

// nftMessage is one parsed reply: the header fields this package reads plus
// the body, which holds a struct nfgenmsg and the attributes after it.
type nftMessage struct {
	Kind uint16
	Seq  uint32
	Pid  uint32
	Data []byte
}

// batch sends one transaction and waits for the kernel to acknowledge every
// message in it. Everything between the batch markers commits together or not
// at all, so a failure leaves the host holding exactly what it held before.
//
// A failure inside the batch is reported against the message that caused it,
// and a failure of the commit itself against the batch marker, so any nonzero
// error in the range this call owns ends it. Acknowledgements left in the
// socket by an earlier call carry earlier sequence numbers and are ignored
// rather than mistaken for this call's.
func (c *nftConn) batch(requests []nftRequest) error {
	if len(requests) == 0 {
		return nil
	}
	marker := putNfgenmsgSubsys(nil, unix.NFPROTO_UNSPEC)
	begin := c.next()
	var buf []byte
	buf = c.appendMessage(buf, unix.NFNL_MSG_BATCH_BEGIN, 0, begin, marker)
	expected := make(map[uint32]bool, len(requests))
	first, last := begin, begin
	for _, request := range requests {
		seq := c.next()
		expected[seq] = true
		last = seq
		buf = c.appendMessage(buf, request.kind, request.flags|unix.NLM_F_ACK, seq, request.body)
	}
	end := c.next()
	last = end
	buf = c.appendMessage(buf, unix.NFNL_MSG_BATCH_END, 0, end, marker)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return err
	}
	for len(expected) > 0 {
		messages, err := c.receive()
		if err != nil {
			return err
		}
		for _, message := range messages {
			if message.Pid != c.pid || message.Seq < first || message.Seq > last {
				continue
			}
			if message.Kind != unix.NLMSG_ERROR {
				continue
			}
			if len(message.Data) < 4 {
				return errors.New("egress: truncated netlink error")
			}
			if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
				return unix.Errno(-code)
			}
			delete(expected, message.Seq)
		}
	}
	return nil
}

// dump sends one query and collects every reply to it, ending at NLMSG_DONE.
func (c *nftConn) dump(kind uint16, body []byte) ([]nftMessage, error) {
	seq := c.next()
	buf := c.appendMessage(nil, kind, unix.NLM_F_DUMP, seq, body)
	if err := unix.Sendto(c.fd, buf, 0, &unix.SockaddrNetlink{Family: unix.AF_NETLINK}); err != nil {
		return nil, err
	}
	var replies []nftMessage
	for {
		messages, err := c.receive()
		if err != nil {
			return nil, err
		}
		for _, message := range messages {
			if message.Seq != seq || message.Pid != c.pid {
				continue
			}
			switch message.Kind {
			case unix.NLMSG_NOOP:
			case unix.NLMSG_DONE:
				return replies, nil
			case unix.NLMSG_ERROR:
				if len(message.Data) < 4 {
					return nil, errors.New("egress: truncated netlink error")
				}
				if code := int32(binary.NativeEndian.Uint32(message.Data)); code != 0 {
					return nil, unix.Errno(-code)
				}
				return replies, nil
			default:
				replies = append(replies, message)
			}
		}
	}
}

func (c *nftConn) next() uint32 {
	c.seq++
	return c.seq
}

// appendMessage writes one netlink message, header and body, padded as the
// kernel expects. The header fields are native endian; everything inside an
// NFTA attribute is not.
func (c *nftConn) appendMessage(buf []byte, kind, flags uint16, seq uint32, body []byte) []byte {
	length := unix.SizeofNlMsghdr + len(body)
	start := len(buf)
	buf = append(buf, make([]byte, nlmsgAlign(length))...)
	binary.NativeEndian.PutUint32(buf[start:], uint32(length))
	binary.NativeEndian.PutUint16(buf[start+4:], kind)
	binary.NativeEndian.PutUint16(buf[start+6:], flags|unix.NLM_F_REQUEST)
	binary.NativeEndian.PutUint32(buf[start+8:], seq)
	binary.NativeEndian.PutUint32(buf[start+12:], c.pid)
	copy(buf[start+unix.SizeofNlMsghdr:], body)
	return buf
}

// receive reads one datagram whole, growing the buffer when the kernel has
// more to say than it currently holds, exactly as internal/kernel does.
func (c *nftConn) receive() ([]nftMessage, error) {
	for {
		n, _, err := unix.Recvfrom(c.fd, c.buf, unix.MSG_PEEK|unix.MSG_TRUNC)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if errors.Is(err, unix.EAGAIN) {
			return nil, errors.New("egress: the kernel did not answer a netfilter netlink request")
		}
		if err != nil {
			return nil, err
		}
		if n <= len(c.buf) {
			break
		}
		c.buf = make([]byte, n)
	}
	for {
		n, from, err := unix.Recvfrom(c.fd, c.buf, 0)
		if errors.Is(err, unix.EINTR) {
			continue
		}
		if err != nil {
			return nil, err
		}
		if sender, ok := from.(*unix.SockaddrNetlink); !ok || sender.Pid != 0 {
			return nil, errors.New("egress: netfilter reply did not come from the kernel")
		}
		return parseMessages(slices.Clone(c.buf[:n]))
	}
}

// parseMessages splits one datagram into messages. A length running past the
// buffer is an error rather than a short read, so a truncated dump can never
// look like a complete one.
func parseMessages(buf []byte) ([]nftMessage, error) {
	var out []nftMessage
	for len(buf) >= unix.SizeofNlMsghdr {
		length := int(binary.NativeEndian.Uint32(buf[0:]))
		if length < unix.SizeofNlMsghdr || length > len(buf) {
			return nil, errors.New("egress: malformed netlink message length")
		}
		out = append(out, nftMessage{
			Kind: binary.NativeEndian.Uint16(buf[4:]),
			Seq:  binary.NativeEndian.Uint32(buf[8:]),
			Pid:  binary.NativeEndian.Uint32(buf[12:]),
			Data: buf[unix.SizeofNlMsghdr:length],
		})
		next := nlmsgAlign(length)
		if next >= len(buf) {
			break
		}
		buf = buf[next:]
	}
	return out, nil
}

// attributes iterates the attributes that follow a fixed header of offset
// bytes. A malformed attribute ends the iteration: the kernel emits none, and
// a half-decoded message fails the name checks that follow rather than being
// acted on.
func (m nftMessage) attributes(offset int) iter.Seq2[uint16, []byte] {
	return func(yield func(uint16, []byte) bool) {
		if len(m.Data) < offset {
			return
		}
		for _, field := range nested(m.Data[offset:]) {
			if !yield(field.kind, field.value) {
				return
			}
		}
	}
}

// attribute is one decoded netlink attribute, with the nested flag already
// masked off its type.
type attribute struct {
	kind  uint16
	value []byte
}

// nested splits an attribute's payload into the attributes inside it.
func nested(buf []byte) []attribute {
	var out []attribute
	for len(buf) >= unix.SizeofRtAttr {
		length := int(binary.NativeEndian.Uint16(buf[0:]))
		kind := binary.NativeEndian.Uint16(buf[2:]) & nlaTypeMask
		if length < unix.SizeofRtAttr || length > len(buf) {
			return out
		}
		out = append(out, attribute{kind: kind, value: buf[unix.SizeofRtAttr:length]})
		next := rtaAlign(length)
		if next >= len(buf) {
			return out
		}
		buf = buf[next:]
	}
	return out
}

// putNfgenmsg writes struct nfgenmsg for an nf_tables message.
func putNfgenmsg(buf []byte, family uint8) []byte {
	return append(buf, family, nfnetlinkV0, 0, 0)
}

// putNfgenmsgSubsys writes the same header for a batch marker, whose res_id
// names the subsystem the transaction belongs to. It is big endian, unlike the
// netlink header around it.
func putNfgenmsgSubsys(buf []byte, family uint8) []byte {
	buf = append(buf, family, nfnetlinkV0, 0, 0)
	binary.BigEndian.PutUint16(buf[len(buf)-2:], uint16(unix.NFNL_SUBSYS_NFTABLES))
	return buf
}

func putAttr(buf []byte, kind uint16, value []byte) []byte {
	length := unix.SizeofRtAttr + len(value)
	start := len(buf)
	buf = append(buf, make([]byte, rtaAlign(length))...)
	binary.NativeEndian.PutUint16(buf[start:], uint16(length))
	binary.NativeEndian.PutUint16(buf[start+2:], kind)
	copy(buf[start+unix.SizeofRtAttr:], value)
	return buf
}

// putAttrBE32 writes a 32-bit attribute in network byte order, which is how
// nf_tables carries every number in an NFTA attribute.
func putAttrBE32(buf []byte, kind uint16, value uint32) []byte {
	var raw [4]byte
	binary.BigEndian.PutUint32(raw[:], value)
	return putAttr(buf, kind, raw[:])
}

func putAttrString(buf []byte, kind uint16, value string) []byte {
	return putAttr(buf, kind, append([]byte(value), 0))
}

func nlmsgAlign(n int) int { return (n + unix.NLMSG_ALIGNTO - 1) &^ (unix.NLMSG_ALIGNTO - 1) }

func rtaAlign(n int) int { return (n + unix.RTA_ALIGNTO - 1) &^ (unix.RTA_ALIGNTO - 1) }
