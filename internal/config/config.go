// Package config defines ranet-lite's own local configuration format.
// Unlike internal/registry (which mirrors ranet's registry.json and key
// files byte-for-byte so a deployment can reuse them unchanged), this file
// format is specific to ranet-lite: a slim client dialing out to one or a
// few existing mesh nodes rather than participating in ranet's full N-to-N
// reconciliation, so its config only needs "who am I" and "who do I dial".
package config

import (
	"errors"
	"fmt"
	"log"
	"net/netip"
	"os"
	"strings"
	"time"

	"github.com/NickCao/ranet-lite/internal/babel"
	"gopkg.in/yaml.v3"
)

type Config struct {
	// Identity: must match an entry in Registry's Nodes for Organization,
	// and PrivateKey must be that organization's shared Ed25519 key.
	Organization string     `yaml:"organization"`
	CommonName   string     `yaml:"common_name"`
	Port         uint16     `yaml:"port"`
	Endpoints    []Endpoint `yaml:"endpoints"`

	PrivateKey string `yaml:"private_key"` // path to a PKCS8 PEM Ed25519 key
	Registry   string `yaml:"registry"`    // path to a ranet registry.json

	Originate []string `yaml:"originate"` // CIDR prefixes this node announces via babel
	// TUN names an existing TUN device to attach to, or the device to create
	// when it does not exist. Empty creates an automatically named ranet%d.
	TUN string `yaml:"tun"`
	// ReplayWindow controls the ESP receive window: omitted uses 4096 for
	// high-speed multicore senders, while an explicit 0 disables checking.
	ReplayWindow *uint32 `yaml:"replay_window"`
	// Rekey intervals default to one hour for Child SAs and three hours for
	// IKE SAs. An explicit zero disables the corresponding proactive rekey.
	ChildRekeyInterval *Duration `yaml:"child_rekey_interval"`
	IKERekeyInterval   *Duration `yaml:"ike_rekey_interval"`
	// Rekeys run before their interval expires: margin is always subtracted
	// and jitter is independently randomized from zero through its value.
	RekeyMargin *Duration `yaml:"rekey_margin"`
	RekeyJitter *Duration `yaml:"rekey_jitter"`
	// A failed scheduled rekey is retried with capped exponential backoff.
	RekeyRetryInitial *Duration `yaml:"rekey_retry_initial"`
	RekeyRetryMax     *Duration `yaml:"rekey_retry_max"`

	// Responder answers peers that dial us. It is off by default because a
	// leaf never needs it: it has no reachable address to be dialed at, and
	// an open responder is the one surface an unauthenticated peer can reach.
	// A full mesh needs it on, since every node both dials and answers.
	Responder bool `yaml:"responder"`

	// FullMesh dials every node the registry names, the N-to-N reconciliation
	// ranet performs. Reach on this fleet needs it: the BIRD side exports only
	// its own directly connected routes, so a node learns a prefix from the
	// node originating it or not at all, and dialing a few exits reaches those
	// exits and nothing behind them. Peers still apply, and an entry there
	// wins for its node, which is the only way to pin a serial_number since a
	// generated peer names none.
	FullMesh bool `yaml:"full_mesh"`

	// FWMark is set with SO_MARK on the one UDP socket carrying IKE and ESP,
	// linux only, so a policy rule can keep the underlay in a table of the
	// operator's choosing. Needed on a node whose mesh address is the only
	// global address of its family: the kernel then sources this socket from
	// it, the fleet's "from <mesh address>" rule sends it to the mesh table,
	// and an exit-announced default there routes the underlay into the tun
	// carrying it. ranet-lite writes no rules, so the matching rule, such as
	// "ip rule add fwmark <mark> lookup main", belongs with the ones the
	// deployment already owns. Pick a mark nothing else on the host uses.
	FWMark uint32 `yaml:"fwmark"`

	Peers  []Peer `yaml:"peers"`
	Babel  Babel  `yaml:"babel"`
	Kernel Kernel `yaml:"kernel"`
	// Experimental is ranet's block, carried so its config parses here.
	Experimental Experimental `yaml:"experimental"`
}

// Kernel configures the optional kernel route reconciler in internal/kernel,
// which mirrors the mesh forwarding table into the routing table on linux and
// into the single FIB on darwin. It is
// off unless enabled, so a deployment that configures routes externally is
// unaffected. Every field is validated by kernel.New at startup.
type Kernel struct {
	Enabled bool `yaml:"enabled"`
	// Table is the routing table the reconciler owns; the fleet uses 200,
	// the table the policy rules and End.DT46 look up.
	Table uint32 `yaml:"table"`
	// Protocol is the rt_proto stamped on every installed route, and the
	// marker that separates this reconciler's routes from everyone else's.
	Protocol uint8 `yaml:"protocol"`
	// Metric is RTA_PRIORITY, and omitting it leaves the kernel default, 0 for
	// IPv4 and 1024 for IPv6. Do not set it to BIRD's 32 while BIRD is still
	// exporting to the same table: both daemons would then key on the same
	// prefix and priority, and since an install refuses a key another writer
	// holds rather than taking it over, whichever daemon got there first keeps
	// the prefix and the other loses it quietly.
	Metric uint32 `yaml:"metric"`
	// PrefSrc4 is RTA_PREFSRC on every installed IPv4 route, taking over from
	// krt_prefsrc on BIRD's kbabel4. IPv6 source-specific routes carry
	// RTA_SRC from the babel source prefix instead.
	PrefSrc4 string `yaml:"prefsrc4"`
	// Addresses are assigned to the TUN and removed again at shutdown; only
	// addresses the reconciler added itself are ever removed.
	Addresses []string `yaml:"addresses"`
	// AssignOriginated assigns every prefix in Originate as well, which is
	// the locally originated address the operator configures by hand today.
	AssignOriginated bool `yaml:"assign_originated"`
	// VRF enslaves the TUN to that master device, but only while the link has
	// no master, so networkd keeps whatever it already claimed.
	VRF string `yaml:"vrf"`
	// ReconcileInterval is the periodic sweep that corrects drift nothing
	// announced. Omitted uses the package default.
	ReconcileInterval *Duration `yaml:"reconcile_interval"`
}

// KernelAddresses keeps startup and reload checking the same assigned-address
// set. Host bits belong to interface addresses, unlike Babel route keys.
func (c *Config) KernelAddresses() ([]netip.Prefix, error) {
	originated := c.Originate
	if !c.Kernel.AssignOriginated {
		originated = nil
	}
	var addresses []netip.Prefix
	seen := make(map[netip.Prefix]bool)
	// A default is announced, never assigned: an exit originates "::/0" from
	// its transit prefix, and assign_originated would otherwise try to put
	// "::/0" on the tun on every pass and fail on every one. The test is the
	// address rather than the prefix length, because a prefix length says
	// nothing about whether an address can be assigned. validate refuses every
	// other zero-length spelling, on both originate lists and on
	// kernel.addresses, so this is the one that is left.
	add := func(prefix netip.Prefix) {
		if prefix.Addr().IsUnspecified() || seen[prefix] {
			return
		}
		seen[prefix] = true
		addresses = append(addresses, prefix)
	}
	for _, raw := range c.Kernel.Addresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("config: kernel.addresses %q: %w", raw, err)
		}
		add(prefix)
	}
	// The originated lists are the same prefixes babel announces, so an entry
	// here is reported as what it is written as rather than as an address.
	for _, raw := range originated {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return nil, fmt.Errorf("config: originate %q: %w", raw, err)
		}
		add(prefix)
	}
	if c.Kernel.AssignOriginated {
		for _, entry := range c.Babel.Originate {
			add(entry.Prefix)
		}
	}
	return addresses, nil
}

// Duration accepts standard Go duration strings and a bare YAML zero.
// The latter keeps `child_rekey_interval: 0` concise when disabling rekeys.
type Duration time.Duration

func (d *Duration) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind != yaml.ScalarNode {
		// Value is empty for a mapping or a sequence, so without this the
		// error is `invalid duration ""` with nothing pointing at the line.
		return fmt.Errorf("line %d: a duration is a scalar such as 4s, not %s", value.Line, nodeKindName(value.Kind))
	}
	if value.Tag == "!!int" && value.Value == "0" {
		*d = 0
		return nil
	}
	parsed, err := time.ParseDuration(value.Value)
	if err != nil {
		return err
	}
	*d = Duration(parsed)
	return nil
}

func nodeKindName(kind yaml.Kind) string {
	switch kind {
	case yaml.MappingNode:
		return "a mapping"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "a document"
	}
}

func (c *Config) ReplayWindowSize() uint32 {
	if c.ReplayWindow == nil {
		return 4096
	}
	return *c.ReplayWindow
}

func (c *Config) ChildRekeyIntervalValue() time.Duration {
	if c.ChildRekeyInterval == nil {
		return time.Hour
	}
	return time.Duration(*c.ChildRekeyInterval)
}

func (c *Config) IKERekeyIntervalValue() time.Duration {
	if c.IKERekeyInterval == nil {
		return 3 * time.Hour
	}
	return time.Duration(*c.IKERekeyInterval)
}

func (c *Config) RekeyMarginValue() time.Duration {
	if c.RekeyMargin == nil {
		return 5 * time.Minute
	}
	return time.Duration(*c.RekeyMargin)
}

func (c *Config) RekeyJitterValue() time.Duration {
	if c.RekeyJitter == nil {
		return time.Minute
	}
	return time.Duration(*c.RekeyJitter)
}

func (c *Config) RekeyRetryInitialValue() time.Duration {
	if c.RekeyRetryInitial == nil {
		return 5 * time.Second
	}
	return time.Duration(*c.RekeyRetryInitial)
}

func (c *Config) RekeyRetryMaxValue() time.Duration {
	if c.RekeyRetryMax == nil {
		return 5 * time.Minute
	}
	return time.Duration(*c.RekeyRetryMax)
}

// Endpoint mirrors the identity portion of ranet's endpoint configuration.
// Socket address selection is global: the transport binds Config.Port for
// every family the platform gives it, one dual-stack socket on darwin and one
// per family on linux, and the kernel selects the source address by route.
// Endpoint carries ranet's own endpoint fields as well as ranet-lite's, so a
// deployment can point this at the `config.json` its module already generates
// rather than maintaining a second description of the same node. The fields
// ranet acts on and this does not are named here rather than left unknown: the
// loader refuses what it does not recognize, and an operator whose file is
// rejected over `updown` learns nothing from "field not found".
type Endpoint struct {
	SerialNumber  string `yaml:"serial_number"`
	AddressFamily string `yaml:"address_family"`
	// Port is ranet's spelling of the one this node listens on. Every endpoint
	// must agree, which ranet's own module already asserts, and it satisfies
	// the top-level port when that is absent.
	Port uint16 `yaml:"port"`
	// Address, UpDown and FWMark are plain strings rather than pointers
	// because absent and empty ask for the same thing, and because Endpoint is
	// compared with == to decide whether a reload may proceed: a pointer would
	// make two loads of one file differ and refuse every reload.
	//
	// Address is the endpoint's public address in ranet's config. The
	// transport binds the wildcard and lets the kernel pick the source by
	// route, so this selects nothing here; a node that sets it is told so once
	// rather than left to wonder.
	Address string `yaml:"address"`
	// UpDown is ranet's per-peer interface hook, which strongSwan runs to
	// create one xfrm interface per Child SA. This binary has one tun for the
	// whole mesh and no per-peer interfaces, so there is nothing for a hook to
	// create and none is run.
	UpDown string `yaml:"updown"`
	// FWMark is ranet's per-endpoint mark, which it passes to strongSwan as
	// set_mark_out. That is an XFRM mark on the outbound SA, not a mark on the
	// socket carrying IKE and ESP, and strongSwan spells it value[/mask] or
	// %unique besides. It is named here so the file is not rejected over it
	// and reported once as having no effect; the top-level fwmark is this
	// tree's own socket mark and is set separately.
	FWMark string `yaml:"fwmark"`
}

// Experimental mirrors ranet's block of the same name so its config parses
// here. Nothing in it is implemented, so anything switched on is refused
// rather than accepted and ignored.
type Experimental struct {
	IPTFS bool `yaml:"iptfs"`
}

type Peer struct {
	// Organization defaults to the top-level Organization if empty —
	// almost always what you want, since ranet shares one keypair across
	// an entire organization; only cross-organization deployments need to
	// override it per peer.
	Organization string `yaml:"organization"`
	CommonName   string `yaml:"common_name"`
	// SerialNumber selects a specific endpoint; if empty, the first
	// endpoint of a matching address family is used.
	SerialNumber string `yaml:"serial_number"`
}

type Babel struct {
	// Spelled with the same Duration as every other interval in this file.
	// yaml.v3 decodes a bare time.Duration from a duration string and from
	// nothing else, so `hello_interval: 0` was a parse error while every other
	// duration in the file takes zero for "leave the default alone", and one
	// block disagreed with itself about the spelling. Zero here still means
	// the speaker's own default.
	HelloInterval  Duration `yaml:"hello_interval"`
	UpdateInterval Duration `yaml:"update_interval"`
	// Link cost, named after the BIRD babel interface options it mirrors: a
	// fixed rxcost plus up to rtt_cost scaled linearly between rtt_min and
	// rtt_max. An unset field keeps the speaker's default.
	RxCost  *uint16   `yaml:"rxcost"`
	RTTCost *uint16   `yaml:"rtt_cost"`
	RTTMin  *Duration `yaml:"rtt_min"`
	RTTMax  *Duration `yaml:"rtt_max"`
	// LinkQuality names the estimator that turns Hello loss into a cost,
	// spelled as BIRD spells it: "etx", which the fleet runs on these same
	// tunnels, or "none" to cost every live link the same whatever it drops.
	LinkQuality string `yaml:"link_quality"`
	// Originate announces source-specific prefixes, which the plain top-level
	// originate list cannot express.
	Originate []OriginatePrefix `yaml:"originate"`
	// NoTransit advertises only this node's own prefixes and never relays a
	// route it learned. The fleet's BIRD already behaves this way, and a leaf
	// wants it. Off by default, because a converted fleet needs the relaying
	// and turning it off silently would break the mesh it is replacing.
	NoTransit bool `yaml:"no_transit"`
}

// maskedDefault refuses a prefix that announces the default route while
// carrying host bits, which is always a typo: originatedKey masks it, so the
// node announces "::/0" to the whole mesh and claims to be its exit. A real
// default is written "::/0" and is refused nothing.
func maskedDefault(prefix netip.Prefix) error {
	if prefix.Bits() != 0 || prefix.Addr().IsUnspecified() {
		return nil
	}
	unspecified := "::"
	if prefix.Addr().Is4() {
		unspecified = "0.0.0.0"
	}
	return fmt.Errorf("announces a default route, write %s/0 to mean that", unspecified)
}

// OriginatePrefix is either a bare CIDR prefix or a mapping carrying a source
// prefix, so both entries below are valid:
//
//	babel:
//	  originate:
//	    - 2001:db8::/48
//	    - prefix: ::/0
//	      from: 2602:f590::/36
type OriginatePrefix struct {
	Prefix netip.Prefix
	From   netip.Prefix
}

func (o *OriginatePrefix) UnmarshalYAML(value *yaml.Node) error {
	if value.Kind == yaml.ScalarNode {
		prefix, err := netip.ParsePrefix(value.Value)
		if err != nil {
			return fmt.Errorf("config: originate %q: %w", value.Value, err)
		}
		if err := maskedDefault(prefix); err != nil {
			return fmt.Errorf("config: originate %q %w", value.Value, err)
		}
		o.Prefix = prefix
		return nil
	}
	if value.Kind != yaml.MappingNode {
		return fmt.Errorf("config: originate entry must be a prefix or a prefix and from mapping")
	}
	// Walked by hand rather than decoded into a helper struct: a nested
	// decoder would not inherit the top-level decoder's rejection of unknown
	// fields.
	for i := 0; i+1 < len(value.Content); i += 2 {
		key, item := value.Content[i], value.Content[i+1]
		target := &o.Prefix
		switch key.Value {
		case "prefix":
		case "from":
			target = &o.From
		default:
			return fmt.Errorf("config: originate: unknown field %q", key.Value)
		}
		prefix, err := netip.ParsePrefix(item.Value)
		if err != nil {
			return fmt.Errorf("config: originate %q: %w", item.Value, err)
		}
		*target = prefix
	}
	// In this order, so an entry whose prefix and from are both wrong names
	// the same one every time it is loaded.
	for _, field := range []struct {
		name   string
		prefix netip.Prefix
	}{{"prefix", o.Prefix}, {"from", o.From}} {
		if !field.prefix.IsValid() {
			continue
		}
		if err := maskedDefault(field.prefix); err != nil {
			return fmt.Errorf("config: originate %s %q %w", field.name, field.prefix, err)
		}
	}
	switch {
	case !o.Prefix.IsValid():
		return fmt.Errorf("config: originate: prefix is required")
	case o.From.IsValid() && o.From.Bits() == 0:
		// originatedKey keeps a source only when it is shorter than the whole
		// address space, so this one is dropped and the entry silently becomes
		// an ordinary announcement of its destination.
		return fmt.Errorf("config: originate %s from %s: a source covering every address is not a source-specific route, drop the from", o.Prefix, o.From)
	case o.From.IsValid() && o.From.Addr().Is4() != o.Prefix.Addr().Is4():
		// The source prefix is encoded under the destination's address
		// encoding, so the pair has no representation on the wire.
		return fmt.Errorf("config: originate %s from %s: mismatched address families", o.Prefix, o.From)
	case o.From.IsValid() && o.Prefix.Addr().Is4():
		// Nothing consumes an IPv4 source-specific route. BIRD's
		// babel_read_source_prefix drops the whole Update unless the channel
		// is NET_IP6_SADR, and it has no IPv4 SADR channel; the Linux IPv4 FIB
		// has no source-address-dependent lookup either, so internal/kernel
		// refuses to install one. Announcing it would be a prefix that
		// reaches nobody.
		return fmt.Errorf("config: originate %s from %s: source-specific routes are IPv6 only", o.Prefix, o.From)
	}
	return nil
}

// SpeakerConfig is the babel configuration this block describes. Cost fields
// left unset keep the speaker's own defaults.
func (b Babel) SpeakerConfig() babel.Config {
	cost := babel.DefaultCostParams()
	if b.RxCost != nil {
		cost.RxCost = *b.RxCost
	}
	if b.RTTCost != nil {
		cost.RTTCost = *b.RTTCost
	}
	if b.RTTMin != nil {
		cost.RTTMin = time.Duration(*b.RTTMin)
	}
	if b.RTTMax != nil {
		cost.RTTMax = time.Duration(*b.RTTMax)
	}
	if b.LinkQuality == "none" {
		cost.LinkQuality = babel.LinkQualityNone
	}
	return babel.Config{HelloInterval: time.Duration(b.HelloInterval),
		UpdateInterval: time.Duration(b.UpdateInterval), Cost: cost, NoTransit: b.NoTransit}
}

// Load reads a configuration. registryPath and privateKeyPath override the
// file's own when non-empty and fullMesh turns that field on, so ranet's
// config.json runs here unchanged: it names none of the three, and ranet takes
// the first two on its own command line and the third by always behaving that
// way.
func Load(path, registryPath, privateKeyPath string, fullMesh bool) (*Config, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("config: read %s: %w", path, err)
	}
	var c Config
	decoder := yaml.NewDecoder(strings.NewReader(string(b)))
	decoder.KnownFields(true)
	if err := decoder.Decode(&c); err != nil {
		return nil, fmt.Errorf("config: parse %s: %w", path, err)
	}
	if err := c.adoptRanetEndpointFields(); err != nil {
		return nil, fmt.Errorf("config: %s: %w", path, err)
	}
	// Applied before validation, not after: ranet's own config file has
	// nowhere to name the registry or the key, so a file that carries neither
	// is valid exactly when the command line supplies them. Both take ranet's
	// spelling, so its file runs here unchanged.
	if registryPath != "" {
		c.Registry = registryPath
	}
	if privateKeyPath != "" {
		c.PrivateKey = privateKeyPath
	}
	if fullMesh {
		c.FullMesh = true
	}
	c.setDefaults()
	return &c, c.validate()
}

// adoptRanetEndpointFields lets ranet's own config.json stand in for this one,
// since valid JSON is valid YAML and the two schemas differ in where they put
// the same facts rather than in the facts themselves. ranet carries the port
// and the socket mark per endpoint while this binds one socket for all of
// them, so each is adopted only when every endpoint agrees and the top-level
// spelling is absent. A disagreement is refused instead of picked from,
// because ranet's own module already asserts that the ports match and a file
// where they do not is one nothing should run.
func (c *Config) adoptRanetEndpointFields() error {
	for _, ep := range c.Endpoints {
		if ep.Port == 0 {
			continue
		}
		switch {
		case c.Port == 0:
			c.Port = ep.Port
		case c.Port != ep.Port:
			return fmt.Errorf("endpoint %q says port %d and the top level says %d", ep.SerialNumber, ep.Port, c.Port)
		}
	}
	for _, ep := range c.Endpoints {
		// Said once per endpoint rather than dropped. Both fields change what
		// ranet does, so a file carrying them was written expecting an effect,
		// and an operator who is not told keeps expecting it.
		if ep.Address != "" {
			log.Printf("config: endpoint %q address %q is not used: the transport binds every interface and lets the kernel pick the source by route", ep.SerialNumber, ep.Address)
		}
		if ep.UpDown != "" {
			log.Printf("config: endpoint %q updown %q is not run: there are no per-peer interfaces here, one tun carries the whole mesh", ep.SerialNumber, ep.UpDown)
		}
		if ep.FWMark != "" {
			log.Printf("config: endpoint %q fwmark %q is not applied: ranet hands that to strongSwan as set_mark_out, an XFRM mark on the outbound SA, and the top-level fwmark here is SO_MARK on the socket, which is a different thing set in a different place", ep.SerialNumber, ep.FWMark)
		}
	}
	if c.Experimental.IPTFS {
		// Accepted as a field so ranet's config parses, refused as a setting
		// because this tree has no IP-TFS: taking it and carrying on would
		// leave a node believing its traffic is padded when it is not.
		return errors.New("experimental.iptfs is not implemented here")
	}
	return nil
}

func (c *Config) setDefaults() {
	for i := range c.Peers {
		if c.Peers[i].Organization == "" {
			c.Peers[i].Organization = c.Organization
		}
	}
}

func (c *Config) validate() error {
	switch {
	case c.Organization == "":
		return fmt.Errorf("config: organization is required")
	case c.CommonName == "":
		return fmt.Errorf("config: common_name is required")
	case c.Port == 0:
		return fmt.Errorf("config: port is required")
	case c.Port == 500:
		// Every IKE datagram here carries the non-ESP marker so IKE and ESP
		// can share one socket, and RFC 7296 section 2.23 says "UDP
		// encapsulation MUST NOT be done on port 500". A peer on 500 would
		// read the marker as the start of a header.
		return fmt.Errorf("config: port 500 cannot carry UDP-encapsulated IKE, use 4500 or a private port")
	case len(c.Endpoints) == 0:
		return fmt.Errorf("config: at least one endpoint is required")
	case c.PrivateKey == "":
		return fmt.Errorf("config: private_key is required")
	case c.Registry == "":
		return fmt.Errorf("config: registry is required")
	case len(c.Peers) == 0 && !c.Responder && !c.FullMesh:
		// A responder needs no peers: it answers whoever the registry knows.
		// Without one, a node with neither would do nothing at all.
		return fmt.Errorf("config: at least one peer is required unless responder or full_mesh is set")
	case c.ReplayWindow != nil && *c.ReplayWindow > 1<<20:
		return fmt.Errorf("config: replay_window must not exceed %d", uint32(1<<20))
	case c.ChildRekeyInterval != nil && time.Duration(*c.ChildRekeyInterval) < 0:
		return fmt.Errorf("config: child_rekey_interval must be nonnegative when set")
	case c.IKERekeyInterval != nil && time.Duration(*c.IKERekeyInterval) < 0:
		return fmt.Errorf("config: ike_rekey_interval must be nonnegative when set")
	case c.RekeyMargin != nil && time.Duration(*c.RekeyMargin) < 0:
		return fmt.Errorf("config: rekey_margin must be nonnegative when set")
	case c.RekeyJitter != nil && time.Duration(*c.RekeyJitter) < 0:
		return fmt.Errorf("config: rekey_jitter must be nonnegative when set")
	case c.RekeyRetryInitial != nil && time.Duration(*c.RekeyRetryInitial) <= 0:
		return fmt.Errorf("config: rekey_retry_initial must be positive when set")
	case c.RekeyRetryMax != nil && time.Duration(*c.RekeyRetryMax) <= 0:
		return fmt.Errorf("config: rekey_retry_max must be positive when set")
	case c.RekeyRetryInitialValue() > c.RekeyRetryMaxValue():
		return fmt.Errorf("config: rekey_retry_initial must not exceed rekey_retry_max")
	case !validRekeyTiming(c.ChildRekeyIntervalValue(), c.RekeyMarginValue(), c.RekeyJitterValue()):
		return fmt.Errorf("config: rekey_margin plus rekey_jitter must be less than child_rekey_interval")
	case !validRekeyTiming(c.IKERekeyIntervalValue(), c.RekeyMarginValue(), c.RekeyJitterValue()):
		return fmt.Errorf("config: rekey_margin plus rekey_jitter must be less than ike_rekey_interval")
	}
	// Validate the whole speaker configuration, link costs included, so a bad
	switch c.Babel.LinkQuality {
	case "", "etx", "none":
	default:
		return fmt.Errorf("config: babel.link_quality %q is not etx or none", c.Babel.LinkQuality)
	}
	// rxcost fails at load rather than at speaker construction.
	if err := c.Babel.SpeakerConfig().Validate(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	endpointSerials := make(map[string]struct{}, len(c.Endpoints))
	for _, ep := range c.Endpoints {
		if ep.SerialNumber == "" || (ep.AddressFamily != "ip4" && ep.AddressFamily != "ip6") {
			return fmt.Errorf("config: endpoints require serial_number and address_family (ip4 or ip6)")
		}
		if _, exists := endpointSerials[ep.SerialNumber]; exists {
			return fmt.Errorf("config: duplicate endpoint serial_number %q", ep.SerialNumber)
		}
		endpointSerials[ep.SerialNumber] = struct{}{}
	}
	peers := make(map[string]struct{}, len(c.Peers))
	for _, peer := range c.Peers {
		if peer.Organization == "" || peer.CommonName == "" {
			return fmt.Errorf("config: peers require organization and common_name")
		}
		key := peer.Organization + "\x00" + peer.CommonName + "\x00" + peer.SerialNumber
		if _, exists := peers[key]; exists {
			return fmt.Errorf("config: duplicate peer %s/%s endpoint %q", peer.Organization, peer.CommonName, peer.SerialNumber)
		}
		peers[key] = struct{}{}
	}
	for _, raw := range c.Originate {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("config: originate %q: %w", raw, err)
		}
		if err := maskedDefault(prefix); err != nil {
			return fmt.Errorf("config: originate %q %w", raw, err)
		}
	}
	for _, raw := range c.Kernel.Addresses {
		prefix, err := netip.ParsePrefix(raw)
		if err != nil {
			return fmt.Errorf("config: kernel.addresses %q: %w", raw, err)
		}
		// Assigning the unspecified address is not something an interface can
		// do, and KernelAddresses skips it, so accepting the entry and
		// dropping it silently is the one outcome that tells the operator
		// nothing. A masked default is refused for the same reason it is in
		// originate: an interface carries the address under a length, and
		// zero is not one an operator can have meant.
		if prefix.Addr().IsUnspecified() {
			return fmt.Errorf("config: kernel.addresses %q is not an address an interface can carry", raw)
		}
		// Its own message rather than maskedDefault's: an entry here is
		// assigned to an interface, never announced, so "write ::/0 if that is
		// what you mean" is advice the check above rejects.
		if prefix.Bits() == 0 {
			return fmt.Errorf("config: kernel.addresses %q has no prefix length, and an interface carries an address under one", raw)
		}
	}
	return nil
}

func validRekeyTiming(interval, margin, jitter time.Duration) bool {
	return interval == 0 || (margin < interval && jitter < interval-margin)
}
