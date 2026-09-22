//go:build linux && !android

package kernel

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"

	"github.com/NickCao/ranet-lite/schema"
	"golang.org/x/sys/unix"
)

// This file is the linux realization of policy routing and of the VRF the mesh
// table is bound to. Both are linux facilities with no equivalent on the other
// platforms this tree builds for, which is why they are optional halves of the
// platform rather than methods every backend has to stub. See ruler and
// vrfMaker in kernel.go for what the other platforms do instead.
//
// Ownership is the same as routes': every rule this file writes carries
// FRA_PROTOCOL set to the reconciler's protocol, a dump keeps only those, and
// a delete carries the protocol too so the kernel refuses a mismatch as well.
// FRA_PROTOCOL has been in the kernel since 4.17 and systemd-networkd sets it
// to RTPROT_STATIC on the rules it installs, so the fleet's own rules and this
// reconciler's are already distinguishable on a running node.

// afInet and afInet6 are AF_INET and AF_INET6, and af is one rule's family as
// this backend writes it into the header. They live with the netlink encoder
// rather than beside the Family type, because a family is a word everywhere
// else in this tree and a number only here.
const (
	afInet  uint8 = 2
	afInet6 uint8 = 10
)

// af never sees an unresolved family: expandRules names one on every rule and
// validate refuses anything else.
func (f Family) af() uint8 {
	if f == FamilyIPv4 {
		return afInet
	}
	return afInet6
}

// sizeofFibRuleHdr is struct fib_rule_hdr, which has the same shape as rtmsg:
// family, dst_len, src_len, tos, table, res1, res2, action, then a 32-bit
// flags field. x/sys/unix exports no type for it, so the twelve bytes are
// written by hand, as routeMessage writes rtmsg.
const sizeofFibRuleHdr = 12

// ruleMessage is the body of an RTM_NEWRULE or RTM_DELRULE for one rule.
//
// The table goes in FRA_TABLE rather than in the one-byte header field, and
// the header field stays RT_TABLE_UNSPEC, which is how a table number above
// 255 reaches the kernel at all. routeMessage splits it the same way.
func (p *netlinkPlatform) ruleMessage(rule Rule) []byte {
	body := make([]byte, sizeofFibRuleHdr)
	body[0] = rule.Family.af()
	if rule.To.IsValid() {
		body[1] = uint8(rule.To.Bits())
	}
	if rule.From.IsValid() {
		body[2] = uint8(rule.From.Bits())
	}
	// body[4] is the legacy table field, left at RT_TABLE_UNSPEC.
	body[7] = unix.FR_ACT_TO_TBL
	body = putAttrU32(body, unix.FRA_PRIORITY, rule.Priority)
	body = putAttrU32(body, unix.FRA_TABLE, uint32(rule.Table))
	body = putAttr(body, unix.FRA_PROTOCOL, []byte{p.table.Proto})
	if rule.To.IsValid() {
		body = putAttr(body, unix.FRA_DST, addressBytes(rule.To.Addr()))
	}
	if rule.From.IsValid() {
		body = putAttr(body, unix.FRA_SRC, addressBytes(rule.From.Addr()))
	}
	if rule.FWMark != 0 {
		body = putAttrU32(body, unix.FRA_FWMARK, rule.FWMark)
		if rule.FWMask != 0 {
			body = putAttrU32(body, unix.FRA_FWMASK, rule.FWMask)
		}
	}
	return body
}

// Rules dumps every policy rule and keeps the ones carrying this reconciler's
// protocol. A rule with no FRA_PROTOCOL, which a kernel older than 4.17 and
// the kernel's own three built-in rules give back, is somebody else's by
// definition: this file never writes one without it.
func (p *netlinkPlatform) Rules() ([]Rule, error) {
	body := make([]byte, sizeofFibRuleHdr)
	body[0] = unix.AF_UNSPEC
	replies, err := p.conn.execute(unix.RTM_GETRULE, unix.NLM_F_DUMP, body)
	if err != nil {
		return nil, fmt.Errorf("kernel: dump rules: %w", err)
	}
	var out []Rule
	for _, reply := range replies {
		if rule, ok := p.decodeRule(reply); ok {
			out = append(out, rule)
		}
	}
	return out, nil
}

// decodeRule reads one dumped rule, and reports false for anything this
// reconciler does not own or could not have written. Everything it accepts has
// to compare equal to the configured rule it came from, or the diff installs a
// duplicate on every pass.
func (p *netlinkPlatform) decodeRule(message nlMessage) (Rule, bool) {
	if len(message.Data) < sizeofFibRuleHdr {
		return Rule{}, false
	}
	family := message.Data[0]
	if family != afInet && family != afInet6 {
		return Rule{}, false
	}
	// Only the action this file writes. A rule that blackholes or that reaches
	// a goto target is not one of ours however it is marked, and deleting it
	// on the strength of a protocol byte alone would be taking somebody's
	// word for what it does.
	if message.Data[7] != unix.FR_ACT_TO_TBL {
		return Rule{}, false
	}
	rule := Rule{Family: FamilyIPv6}
	if family == afInet {
		rule.Family = FamilyIPv4
	}
	dstLen, srcLen := message.Data[1], message.Data[2]
	ours := false
	for kind, value := range message.attributes(sizeofFibRuleHdr) {
		switch kind {
		case unix.FRA_PROTOCOL:
			ours = len(value) == 1 && value[0] == p.table.Proto
		case unix.FRA_TABLE:
			if len(value) == 4 {
				rule.Table = schema.TableID(binary.NativeEndian.Uint32(value))
			}
		case unix.FRA_PRIORITY:
			if len(value) == 4 {
				rule.Priority = binary.NativeEndian.Uint32(value)
			}
		case unix.FRA_FWMARK:
			if len(value) == 4 {
				rule.FWMark = binary.NativeEndian.Uint32(value)
			}
		case unix.FRA_FWMASK:
			if len(value) == 4 {
				rule.FWMask = binary.NativeEndian.Uint32(value)
			}
		case unix.FRA_DST:
			if address, ok := addressFromBytes(value); ok {
				rule.To = schema.PrefixFrom(netip.PrefixFrom(address, int(dstLen)))
			}
		case unix.FRA_SRC:
			if address, ok := addressFromBytes(value); ok {
				rule.From = schema.PrefixFrom(netip.PrefixFrom(address, int(srcLen)))
			}
		}
	}
	if !ours || rule.Table == 0 || rule.Priority == 0 {
		return Rule{}, false
	}
	// A mask the kernel reports as all ones is the exact match an absent
	// FRA_FWMASK asks for, so the two spellings compare equal rather than
	// making every pass delete and reinstall the same rule.
	if rule.FWMask == ^uint32(0) {
		rule.FWMask = 0
	}
	return rule, true
}

func (p *netlinkPlatform) AddRule(rule Rule) error {
	_, err := p.conn.execute(unix.RTM_NEWRULE,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, p.ruleMessage(rule))
	// EEXIST is a rule already in place under the same selectors, which a pass
	// that raced its own notification reaches. The diff wanted it there.
	if errors.Is(err, unix.EEXIST) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("kernel: add rule %s: %w", rule, err)
	}
	return nil
}

func (p *netlinkPlatform) DelRule(rule Rule) error {
	_, err := p.conn.execute(unix.RTM_DELRULE, unix.NLM_F_ACK, p.ruleMessage(rule))
	if errors.Is(err, unix.ENOENT) || errors.Is(err, unix.ESRCH) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("kernel: delete rule %s: %w", rule, err)
	}
	return nil
}

// EnsureVRF creates the device when nothing of that name exists. A device that
// is already there is left exactly as it is, whatever kind it is and whatever
// table it is bound to: rebinding somebody else's VRF moves every route in it,
// and replacing a device of another kind takes its addresses with it.
func (p *netlinkPlatform) EnsureVRF(name string, table uint32) (bool, error) {
	if _, _, err := p.conn.link(name); err == nil {
		return false, nil
	} else if !errors.Is(err, unix.ENODEV) {
		return false, fmt.Errorf("kernel: look up %s: %w", name, err)
	}
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	// IFF_UP in the change mask and the flags, so the device is usable as a
	// master the moment it exists rather than after a second call.
	binary.NativeEndian.PutUint32(body[8:], unix.IFF_UP)
	binary.NativeEndian.PutUint32(body[12:], unix.IFF_UP)
	body = putAttrString(body, unix.IFLA_IFNAME, name)
	data := putAttrU32(nil, unix.IFLA_VRF_TABLE, table)
	info := putAttrString(nil, unix.IFLA_INFO_KIND, "vrf")
	info = putAttr(info, unix.IFLA_INFO_DATA, data)
	body = putAttr(body, unix.IFLA_LINKINFO, info)
	if _, err := p.conn.execute(unix.RTM_NEWLINK,
		unix.NLM_F_CREATE|unix.NLM_F_EXCL|unix.NLM_F_ACK, body); err != nil {
		// Something else won the race between the lookup and the create, which
		// is a device that now exists and is therefore not ours to have made.
		if errors.Is(err, unix.EEXIST) {
			return false, nil
		}
		return false, fmt.Errorf("kernel: create vrf %s: %w", name, err)
	}
	return true, nil
}

func (p *netlinkPlatform) RemoveVRF(name string) error {
	index, _, err := p.conn.link(name)
	if errors.Is(err, unix.ENODEV) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("kernel: look up %s: %w", name, err)
	}
	body := make([]byte, unix.SizeofIfInfomsg)
	body[0] = unix.AF_UNSPEC
	binary.NativeEndian.PutUint32(body[4:], index)
	if _, err := p.conn.execute(unix.RTM_DELLINK, unix.NLM_F_ACK, body); err != nil {
		if errors.Is(err, unix.ENODEV) {
			return nil
		}
		return fmt.Errorf("kernel: remove vrf %s: %w", name, err)
	}
	return nil
}
