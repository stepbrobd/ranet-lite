package config

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/BurntSushi/toml"
	"gopkg.in/yaml.v3"

	"github.com/NickCao/ranet-lite/internal/babel"
	"github.com/NickCao/ranet-lite/internal/ike"
	"github.com/NickCao/ranet-lite/internal/kernel"
	"github.com/NickCao/ranet-lite/internal/schema"
	"github.com/NickCao/ranet-lite/internal/srv6"
	"github.com/NickCao/ranet-lite/internal/transport"
)

// The node a test starts from, in both spellings. Everything below adds one
// capability to it, so a refusal is about the capability rather than about
// what the node forgot to say.
const (
	nodeYAML = `
node:
  org: example
  name: laptop
auth:
  key: key.pem
  trust: trust.json
link:
  port: 13000
  endpoints:
    - serial: "0"
      family: ip4
dial:
  to:
    - name: gateway
`
	nodeTOML = `
[node]
org = "example"
name = "laptop"
[auth]
key = "key.pem"
trust = "trust.json"
[link]
port = 13000
endpoints = [{ serial = "0", family = "ip4" }]
[dial]
to = [{ name = "gateway" }]
`
)

// load writes a body under the extension it is written in and reads it back
// the way the daemon does, through the loader rather than through a decoder,
// so the test covers the dispatch and the validation as well as the parse.
func load(t *testing.T, extension, body string) (*Config, error) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config"+extension)
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	return Load(path)
}

func loadYAML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	return load(t, ".yaml", body)
}

func loadTOML(t *testing.T, body string) (*Config, error) {
	t.Helper()
	return load(t, ".toml", body)
}

// A configuration is read by its extension, and one the loader does not know
// is refused by name rather than sniffed: a file whose contents and whose name
// disagree is one somebody has to debug.
func TestLoaderPicksTheDecoderByExtension(t *testing.T) {
	for _, extension := range []string{".yaml", ".yml", ".json"} {
		if _, err := load(t, extension, nodeYAML); err != nil {
			t.Errorf("%s was refused: %v", extension, err)
		}
	}
	if _, err := loadTOML(t, nodeTOML); err != nil {
		t.Errorf("toml was refused: %v", err)
	}
	// The body is valid YAML, so only the name decides.
	_, err := load(t, ".conf", nodeYAML)
	if err == nil {
		t.Fatal("an extension the loader does not know was sniffed rather than refused")
	}
	if !strings.Contains(err.Error(), ".conf") {
		t.Errorf("the refusal reads %q and does not name the extension", err)
	}
}

// One node written twice reaches one struct. This is the property the second
// decoder exists for: a deployment that writes toml and a control plane that
// speaks json describe the same node.
func TestBothDecodersReadOneNode(t *testing.T) {
	const capabilitiesYAML = `
cap:
  route:
    announce: ["10.66.0.5/32", { prefix: "::/0", from: "2001:db8:1::/48" }]
    transit: false
  babel:
    hello: 4s
    quality: none
    cost:
      rx: 96
      rtt: { weight: 1024, min: 10ms, max: 1024ms }
  table:
    id: 200
    addresses: ["10.66.0.5/32"]
    vrf: { name: mesh, create: true }
    rules:
      - { fwmark: 0x726c, table: main, priority: 40, family: both }
  segment:
    source: "3fff:1:69c:8c0::1"
    local:
      - { sid: "3fff:1:69c:8c6::1", behavior: "End.DT46" }
  crypto:
    replay: 4096
    rekey: { child: 1h, retry: { first: 5s, max: 5m } }
`
	const capabilitiesTOML = `
[cap.route]
announce = ["10.66.0.5/32", { prefix = "::/0", from = "2001:db8:1::/48" }]
transit = false
[cap.babel]
hello = "4s"
quality = "none"
[cap.babel.cost]
rx = 96
[cap.babel.cost.rtt]
weight = 1024
min = "10ms"
max = "1024ms"
[cap.table]
id = 200
addresses = ["10.66.0.5/32"]
vrf = { name = "mesh", create = true }
rules = [{ fwmark = 0x726c, table = "main", priority = 40, family = "both" }]
[cap.segment]
source = "3fff:1:69c:8c0::1"
local = [{ sid = "3fff:1:69c:8c6::1", behavior = "End.DT46" }]
[cap.crypto]
replay = 4096
rekey = { child = "1h", retry = { first = "5s", max = "5m" } }
`
	fromYAML, err := loadYAML(t, nodeYAML+capabilitiesYAML)
	if err != nil {
		t.Fatalf("yaml: %v", err)
	}
	fromTOML, err := loadTOML(t, nodeTOML+capabilitiesTOML)
	if err != nil {
		t.Fatalf("toml: %v", err)
	}
	if !reflect.DeepEqual(fromYAML, fromTOML) {
		t.Errorf("yaml read\n%+v\nand toml read\n%+v", fromYAML, fromTOML)
	}
	// And the capabilities are actually there, so two empty structs cannot
	// pass the comparison above.
	if fromYAML.Cap.Route == nil || fromYAML.Cap.Babel == nil || fromYAML.Cap.Table == nil ||
		fromYAML.Cap.Segment == nil || fromYAML.Cap.Crypto == nil {
		t.Fatalf("a capability was dropped: %+v", fromYAML.Cap)
	}
	if fromYAML.Routes().Transits() || fromYAML.Babel().Quality != babel.LinkQualityNone {
		t.Error("the capability values did not reach the struct")
	}
}

// parse(render(x)) is x under both decoders, for every capability. It is the
// property that makes a generated configuration and a hand written one the
// same thing, and the one that catches a field whose two halves disagree: a
// prefix that renders as empty, a duration that renders as a number.
func TestRenderedCapabilitiesParseBackToThemselves(t *testing.T) {
	node := func() Config {
		return Config{
			Node: Node{Org: "example", Name: "laptop"},
			Auth: Auth{Key: "key.pem", Trust: "trust.json"},
			Link: Link{
				Port:      13000,
				Listen:    true,
				TUN:       "ranet0",
				Underlay:  transport.Underlay{Mark: 0x726c},
				Endpoints: []Endpoint{{Serial: "0", Family: "ip4"}},
			},
			Dial: Dial{All: true, To: []Peer{{Org: "example", Name: "gateway", Serial: "1"}}},
		}
	}
	transit := false
	replay := uint32(2048)
	child := schema.Duration(90 * time.Minute)
	retry := schema.Duration(7 * time.Second)
	for name, capability := range map[string]func(*Config){
		"nothing at all": func(*Config) {},
		"cap.route": func(c *Config) {
			c.Cap.Route = &babel.Routes{
				Announce: []schema.Announce{
					{Prefix: schema.MustPrefix("10.66.0.5/32")},
					{Prefix: schema.MustPrefix("::/0"), From: schema.MustPrefix("2001:db8:1::/48")},
				},
				Transit: &transit,
			}
		},
		"cap.babel": func(c *Config) {
			c.Cap.Babel = &babel.Config{
				Hello:   schema.Duration(4 * time.Second),
				Update:  schema.Duration(16 * time.Second),
				Quality: babel.LinkQualityNone,
				Cost: babel.CostParams{RxCost: 96, RTT: babel.RTTCost{
					Weight: 1024,
					Min:    schema.Duration(10 * time.Millisecond),
					Max:    schema.Duration(1024 * time.Millisecond),
				}},
			}
		},
		"cap.table": func(c *Config) {
			c.Cap.Table = &kernel.Table{
				ID:              200,
				Proto:           155,
				Metric:          64,
				PrefSrc4:        schema.MustAddr("10.66.0.5"),
				Addresses:       []schema.Prefix{schema.MustPrefix("10.66.0.5/32")},
				AssignAnnounced: true,
				VRF:             &kernel.VRF{Name: "mesh", Create: true},
				Reconcile:       schema.Duration(30 * time.Second),
				Rules: []kernel.Rule{
					{FWMark: 0x726c, Table: schema.TableMain, Priority: 40, Family: kernel.FamilyBoth},
					{To: schema.MustPrefix("3fff:1:69c::/48"), Table: 200, Priority: 100},
				},
			}
		},
		"cap.segment": func(c *Config) {
			c.Cap.Segment = &srv6.Segments{
				Source: schema.MustAddr("3fff:1:69c:8c0::1"),
				Local: []srv6.Segment{
					{SID: schema.MustAddr("3fff:1:69c:8c6::1"), Behavior: srv6.BehaviorEndDT46},
					{SID: schema.MustAddr("3fff:1:69c:8c6::2"), Behavior: srv6.BehaviorEnd},
				},
				Steer: []srv6.Steer{{
					From: schema.MustPrefix("3fff:a::198:18:104:117/128"),
					Via:  []schema.Addr{schema.MustAddr("3fff:1:69c:98d6::1")},
				}},
			}
		},
		"cap.crypto": func(c *Config) {
			c.Cap.Crypto = &ike.Crypto{
				Replay: &replay,
				Rekey: ike.Rekey{
					Child: &child,
					Retry: ike.Retry{First: &retry, Max: &child},
				},
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			want := node()
			capability(&want)
			for _, rendered := range []struct {
				extension string
				render    func(any) ([]byte, error)
			}{
				{".yaml", yaml.Marshal},
				{".toml", renderTOML},
			} {
				body, err := rendered.render(&want)
				if err != nil {
					t.Fatalf("render %s: %v", rendered.extension, err)
				}
				got, err := load(t, rendered.extension, string(body))
				if err != nil {
					t.Fatalf("parse %s:\n%s\n%v", rendered.extension, body, err)
				}
				if !reflect.DeepEqual(*got, want) {
					t.Errorf("%s round trip gave\n%+v\nfrom\n%s", rendered.extension, *got, body)
				}
			}
		})
	}
}

func renderTOML(value any) ([]byte, error) {
	var out strings.Builder
	if err := toml.NewEncoder(&out).Encode(value); err != nil {
		return nil, err
	}
	return []byte(out.String()), nil
}

// Every refusal below is a configuration that loads into a node doing
// something other than what its file says, and both decoders have to make the
// same one: an operator who picks the other extension gets the same answer.
func TestBothDecodersRefuseTheSameConfigurations(t *testing.T) {
	for name, pair := range map[string]struct{ asYAML, asTOML string }{
		"an unknown field": {
			asYAML: "unknown: true\n",
			asTOML: "unknown = true\n",
		},
		"an unknown capability": {
			asYAML: "cap:\n  egres:\n    source4: auto\n",
			asTOML: "[cap.egres]\nsource4 = \"auto\"\n",
		},
		"a negative hello interval": {
			asYAML: "cap:\n  babel:\n    hello: -1s\n",
			asTOML: "[cap.babel]\nhello = \"-1s\"\n",
		},
		"an unrepresentable update interval": {
			asYAML: "cap:\n  babel:\n    update: 11m\n",
			asTOML: "[cap.babel]\nupdate = \"11m\"\n",
		},
		"a link quality that is neither": {
			asYAML: "cap:\n  babel:\n    quality: best\n",
			asTOML: "[cap.babel]\nquality = \"best\"\n",
		},
		"an oversized replay window": {
			asYAML: "cap:\n  crypto:\n    replay: 1048577\n",
			asTOML: "[cap.crypto]\nreplay = 1048577\n",
		},
		"an announcement that is not a prefix": {
			asYAML: "cap:\n  route:\n    announce: [not-a-prefix]\n",
			asTOML: "[cap.route]\nannounce = [\"not-a-prefix\"]\n",
		},
		"a segment source that is not an address": {
			asYAML: "cap:\n  segment:\n    source: \"not an address\"\n",
			asTOML: "[cap.segment]\nsource = \"not an address\"\n",
		},
		"a v4 segment source": {
			asYAML: "cap:\n  segment:\n    source: 10.0.0.1\n",
			asTOML: "[cap.segment]\nsource = \"10.0.0.1\"\n",
		},
		"a multicast segment source": {
			asYAML: "cap:\n  segment:\n    source: ff02::1\n",
			asTOML: "[cap.segment]\nsource = \"ff02::1\"\n",
		},
		"an address no interface can carry": {
			asYAML: "cap:\n  table:\n    addresses: [\"::/0\"]\n",
			asTOML: "[cap.table]\naddresses = [\"::/0\"]\n",
		},
		"an address with no prefix length": {
			asYAML: "cap:\n  table:\n    addresses: [\"2001:db8::1/0\"]\n",
			asTOML: "[cap.table]\naddresses = [\"2001:db8::1/0\"]\n",
		},
		"a vrf naming no device": {
			asYAML: "cap:\n  table:\n    vrf: { create: true }\n",
			asTOML: "[cap.table.vrf]\ncreate = true\n",
		},
		"a rule selecting on a mark with no family": {
			asYAML: "cap:\n  table:\n    rules: [{ fwmark: 0x726c, table: main, priority: 40 }]\n",
			asTOML: "[cap.table]\nrules = [{ fwmark = 0x726c, table = \"main\", priority = 40 }]\n",
		},
		"a rule naming a family and an address": {
			asYAML: "cap:\n  table:\n    rules: [{ to: \"10.0.0.0/8\", table: 200, priority: 40, family: ipv6 }]\n",
			asTOML: "[cap.table]\nrules = [{ to = \"10.0.0.0/8\", table = 200, priority = 40, family = \"ipv6\" }]\n",
		},
		"a rule at the local table's priority": {
			asYAML: "cap:\n  table:\n    rules: [{ to: \"10.0.0.0/8\", table: 200, priority: 0 }]\n",
			asTOML: "[cap.table]\nrules = [{ to = \"10.0.0.0/8\", table = 200, priority = 0 }]\n",
		},
		"two rules that are one rule": {
			asYAML: "cap:\n  table:\n    rules:\n      - { to: \"10.0.0.0/8\", table: 200, priority: 40 }\n      - { to: \"10.0.0.0/8\", table: 200, priority: 40 }\n",
			asTOML: "[cap.table]\nrules = [{ to = \"10.0.0.0/8\", table = 200, priority = 40 }, { to = \"10.0.0.0/8\", table = 200, priority = 40 }]\n",
		},
		"a negative rekey interval": {
			asYAML: "cap:\n  crypto:\n    rekey: { child: -1s }\n",
			asTOML: "[cap.crypto.rekey]\nchild = \"-1s\"\n",
		},
		"a zero retry delay": {
			asYAML: "cap:\n  crypto:\n    rekey: { retry: { first: 0 } }\n",
			asTOML: "[cap.crypto.rekey.retry]\nfirst = \"0\"\n",
		},
		"a first retry past the maximum": {
			asYAML: "cap:\n  crypto:\n    rekey: { retry: { first: 1m, max: 5s } }\n",
			asTOML: "[cap.crypto.rekey.retry]\nfirst = \"1m\"\nmax = \"5s\"\n",
		},
		"a rekey with no room for its margin": {
			asYAML: "cap:\n  crypto:\n    rekey: { child: 5m }\n",
			asTOML: "[cap.crypto.rekey]\nchild = \"5m\"\n",
		},
		"a segment this node also carries as an address": {
			asYAML: "cap:\n  table:\n    addresses: [\"3fff:1:69c:8c6::1/128\"]\n  segment:\n    local: [{ sid: \"3fff:1:69c:8c6::1\", behavior: End }]\n",
			asTOML: "[cap.table]\naddresses = [\"3fff:1:69c:8c6::1/128\"]\n[cap.segment]\nlocal = [{ sid = \"3fff:1:69c:8c6::1\", behavior = \"End\" }]\n",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+pair.asYAML); err == nil {
				t.Errorf("yaml took %q", pair.asYAML)
			}
			if _, err := loadTOML(t, nodeTOML+pair.asTOML); err == nil {
				t.Errorf("toml took %q", pair.asTOML)
			}
		})
	}
}

// What the node itself has to say, and what it may not say twice.
func TestNodeFactsAreRefusedWhenTheyCannotBeActedOn(t *testing.T) {
	for name, body := range map[string]string{
		"no org":   strings.Replace(nodeYAML, "  org: example\n", "", 1),
		"no name":  strings.Replace(nodeYAML, "  name: laptop\n", "", 1),
		"no port":  strings.Replace(nodeYAML, "  port: 13000\n", "", 1),
		"no key":   strings.Replace(nodeYAML, "  key: key.pem\n", "", 1),
		"no trust": strings.Replace(nodeYAML, "  trust: trust.json\n", "", 1),
		// Every IKE datagram here carries the non-ESP marker, and RFC 7296
		// section 2.23 forbids UDP encapsulation on port 500, so a node naming
		// it is one no conformant peer can talk to.
		"port 500":     strings.Replace(nodeYAML, "port: 13000", "port: 500", 1),
		"no endpoints": strings.Replace(nodeYAML, "  endpoints:\n    - serial: \"0\"\n      family: ip4\n", "  endpoints: []\n", 1),
		"no peer name": strings.Replace(nodeYAML, "    - name: gateway\n", "    - org: example\n", 1),
		"a duplicate endpoint": strings.Replace(nodeYAML, "    - serial: \"0\"\n      family: ip4\n",
			"    - serial: \"0\"\n      family: ip4\n    - serial: \"0\"\n      family: ip4\n", 1),
		"a duplicate peer":                   strings.Replace(nodeYAML, "    - name: gateway\n", "    - name: gateway\n    - name: gateway\n", 1),
		"an endpoint family that is neither": strings.Replace(nodeYAML, "family: ip4", "family: ipv4", 1),
		// A listener needs no peers, and a node with neither does nothing at
		// all.
		"nothing to dial and nothing listening": strings.Replace(nodeYAML, "dial:\n  to:\n    - name: gateway\n", "", 1),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err == nil {
				t.Error("a node that could not run was accepted")
			}
		})
	}
	// The two that make a node with no peers legitimate.
	alone := strings.Replace(nodeYAML, "dial:\n  to:\n    - name: gateway\n", "", 1)
	for name, body := range map[string]string{
		"a listener": strings.Replace(alone, "  port: 13000\n", "  port: 13000\n  listen: true\n", 1),
		"dial.all":   alone + "dial:\n  all: true\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, body); err != nil {
				t.Errorf("a node that answers or dials everybody was refused: %v", err)
			}
		})
	}
}

// An announcement that cannot mean what it looks like. Each of these loads
// into a node announcing something other than what its file says, and the
// mapping spelling is the one an exit actually uses.
func TestAnnouncementsRefuseWhatTheyCannotMean(t *testing.T) {
	for name, entry := range map[string]string{
		// originatedKey masks, so this announces "::/0" and claims the exit.
		"a masked default":        `"2001:db8::1/0"`,
		"a masked default, v4":    `"198.51.100.1/0"`,
		"a masked default source": `{ prefix: "2001:db8::/48", from: "2001:db8::1/0" }`,
		// A source covering every address is kept by nothing: originatedKey
		// drops it and the entry becomes an ordinary announcement.
		"a source covering everything": `{ prefix: "2001:db8::/48", from: "::/0" }`,
		// Neither family has a lookup that could express this, and installing
		// it as an ordinary route would steal traffic from every other source.
		"mismatched families": `{ prefix: "::/0", from: "10.0.0.0/8" }`,
		// BIRD drops the whole Update without an IPv4 SADR channel, and the
		// IPv4 FIB has no source-specific lookup for the reconciler to install
		// into, so this reaches nobody.
		"an IPv4 source-specific announcement": `{ prefix: "0.0.0.0/0", from: "198.51.100.0/24" }`,
		// A key nobody reads is a prefix nobody announces, and the operator
		// has no way to tell from the outside.
		"an unknown field":  `{ prefix: "::/0", form: "2001:db8::/48" }`,
		"no prefix at all":  `{ from: "2001:db8::/48" }`,
		"not a prefix":      `"2001:db8::1"`,
		"a sequence inside": `[2001:db8::/48]`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+"cap:\n  route:\n    announce:\n      - "+entry+"\n"); err == nil {
				t.Error("the config loaded, so nothing says this cannot mean what it looks like")
			}
		})
	}
	// The spellings that do mean what they say stay accepted.
	for name, entry := range map[string]string{
		"a real default":                   `"::/0"`,
		"a plain announcement":             `"2001:db8::/48"`,
		"a source-specific default":        `{ prefix: "::/0", from: "2001:db8::/48" }`,
		"an address written as a /128":     `"2001:db8::1/128"`,
		"a v4 address written as a /32":    `"10.66.0.5/32"`,
		"a source shorter than the prefix": `{ prefix: "2001:db8::/48", from: "2001:db8:1::/64" }`,
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+"cap:\n  route:\n    announce:\n      - "+entry+"\n"); err != nil {
				t.Errorf("a well-formed announcement was refused: %v", err)
			}
		})
	}
}

// An address is assigned to a device and never announced, so the refusal for
// one written with no prefix length must not tell the operator to write a
// default instead: that is the advice for an announcement, and the check above
// it refuses exactly what it would produce.
func TestAssignedAddressRefusalDoesNotAdviseADefault(t *testing.T) {
	_, err := loadYAML(t, nodeYAML+"cap:\n  table:\n    addresses: [\"2001:db8::1/0\"]\n")
	if err == nil {
		t.Fatal("a masked default was accepted as an address")
	}
	if strings.Contains(err.Error(), "announces a default route") {
		t.Errorf("the refusal tells the operator to write a default: %v", err)
	}
	if !strings.Contains(err.Error(), "cap.table addresses") {
		t.Errorf("the refusal reads %q and does not name the field", err)
	}
}

// Both fields of one entry can be wrong, and which one the refusal names has
// to be the same on every load: iterating a map named a random one, so an
// operator fixing what the message pointed at got a different message next
// time, and any test asserting the text would flake.
func TestAnnouncementRefusalNamesTheSameFieldEveryTime(t *testing.T) {
	body := nodeYAML + "cap:\n  route:\n    announce:\n      - { prefix: \"2001:db8::1/0\", from: \"2001:db8::2/0\" }\n"
	path := filepath.Join(t.TempDir(), "config.yaml")
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	var first string
	for attempt := range 40 {
		_, err := Load(path)
		if err == nil {
			t.Fatal("an entry whose prefix and from are both masked defaults was accepted")
		}
		if attempt == 0 {
			first = err.Error()
			continue
		}
		if err.Error() != first {
			t.Fatalf("load %d said %q, where the first said %q", attempt, err, first)
		}
	}
}

// A file assembled by concatenation ends in a separator, and the document
// after it carries nothing. Refusing it refuses a configuration that is whole,
// and every later SIGHUP with it.
func TestConfigurationEndingInASeparatorIsTaken(t *testing.T) {
	for name, tail := range map[string]string{
		"a bare separator":          "---\n",
		"a separator and a comment": "---\n# nothing here\n",
		"an end of document marker": "...\n",
		"trailing blank lines":      "\n\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := loadYAML(t, nodeYAML+tail); err != nil {
				t.Errorf("a configuration ending in %q was refused: %v", tail, err)
			}
		})
	}
	// A second document is not. A file half pasted below a stray separator
	// would otherwise start on the first half alone and validate cleanly, so
	// the node comes up with the listener off or the wrong peer set and
	// nothing says so.
	if _, err := loadYAML(t, nodeYAML+"---\nlink:\n  listen: false\n"); err == nil {
		t.Error("a second document was accepted")
	}
}

// A capability is on because its block is there. There is no enabled field to
// forget, which is the failure the old one had: a node that configured the
// reconciler and left it off came up with a working mesh, no rules and no
// message.
func TestCapabilityIsOnBecauseItsBlockIsThere(t *testing.T) {
	cfg, err := loadYAML(t, nodeYAML)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cap.Table != nil || cfg.Cap.Segment != nil || cfg.Cap.Crypto != nil {
		t.Fatalf("a node that asked for nothing got %+v", cfg.Cap)
	}
	// And the defaults an absent block stands for are the ones a subsystem
	// documents, rather than a zero that means something else.
	if !cfg.Routes().Transits() {
		t.Error("a node with no cap.route refuses to carry the mesh")
	}
	if cfg.Babel().HelloInterval() != 4*time.Second {
		t.Errorf("a node with no cap.babel runs a %s hello interval", cfg.Babel().HelloInterval())
	}
	if cfg.Crypto().ReplayWindow() != ike.DefaultReplayWindow {
		t.Errorf("a node with no cap.crypto runs a %d packet replay window", cfg.Crypto().ReplayWindow())
	}
	// An empty block is still the capability turned on.
	cfg, err = loadYAML(t, nodeYAML+"cap:\n  table: {}\n")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Cap.Table == nil {
		t.Error("an empty cap.table left the reconciler off")
	}
}

// The link cost surface exists so a node can look as expensive as the speaker
// it replaces. Nothing else reads these four fields, so without this they
// could all be dropped with every other check still green, and a node
// configured to match its peers would silently run on defaults.
func TestBabelCostFieldsReachTheSpeaker(t *testing.T) {
	cfg, err := loadYAML(t, nodeYAML+`cap:
  babel:
    hello: 3s
    update: 9s
    cost:
      rx: 42
      rtt: { weight: 4242, min: 7ms, max: 77ms }
`)
	if err != nil {
		t.Fatal(err)
	}
	speaker := cfg.Babel()
	cost := speaker.CostEffective()
	if cost.RxCost != 42 || cost.RTT.Weight != 4242 {
		t.Errorf("the costs reached the speaker as %d and %d, want 42 and 4242", cost.RxCost, cost.RTT.Weight)
	}
	if cost.RTT.Min.Duration() != 7*time.Millisecond || cost.RTT.Max.Duration() != 77*time.Millisecond {
		t.Errorf("the rtt window reached the speaker as %s..%s, want 7ms..77ms", cost.RTT.Min, cost.RTT.Max)
	}
	if speaker.HelloInterval() != 3*time.Second || speaker.UpdateInterval() != 9*time.Second {
		t.Errorf("the intervals reached the speaker as %s/%s, want 3s/9s",
			speaker.HelloInterval(), speaker.UpdateInterval())
	}
	// Omitted, the speaker's own defaults stand, matching BIRD.
	if bare := (babel.Config{}).CostEffective(); bare != babel.DefaultCostParams() {
		t.Errorf("an empty block changed the defaults to %+v", bare)
	}
}

// A timer written as a bare zero disables it, which is the one spelling an
// operator uses for that and the one every other duration in the file takes.
func TestZeroRekeyIntervalDisablesIt(t *testing.T) {
	cfg, err := loadYAML(t, nodeYAML+"cap:\n  crypto:\n    rekey: { child: 0, ike: 0 }\n")
	if err != nil {
		t.Fatalf("a disabled rekey was refused: %v", err)
	}
	if cfg.Crypto().ChildInterval() != 0 || cfg.Crypto().IKEInterval() != 0 {
		t.Errorf("the rekeys are %s and %s, want both off",
			cfg.Crypto().ChildInterval(), cfg.Crypto().IKEInterval())
	}
	// And a disabled interval has no schedule for the margin to fit inside,
	// so a margin longer than the interval is no longer a contradiction.
	if _, err := loadYAML(t, nodeYAML+"cap:\n  crypto:\n    rekey: { child: 0, margin: 1h, jitter: 1h }\n"); err != nil {
		t.Errorf("a margin beside a disabled rekey was refused: %v", err)
	}
}
