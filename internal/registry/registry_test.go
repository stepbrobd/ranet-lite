package registry

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// TestLoadRegistry exercises the real-world edge cases a production ranet
// registry actually contains (verified against one during development,
// which is not checked in here since registries list real deployments'
// public keys and addresses): null addresses, empty-string addresses
// (distinct from null), hostnames, literal IPv4/IPv6 addresses, and
// non-sequential serial numbers.
func TestLoadRegistry(t *testing.T) {
	reg, err := Load("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	if len(reg) == 0 {
		t.Fatal("no organizations parsed")
	}

	org, ok := reg.FindOrganization("example")
	if !ok {
		t.Fatal("organization \"example\" not found")
	}
	if _, err := org.ParsePublicKey(); err != nil {
		t.Fatalf("parse example public key: %v", err)
	}

	// A node with address: null — no known address yet. ResolveRemote
	// must fail gracefully, not panic.
	noAddr, ok := org.FindNode("no-address-yet")
	if !ok {
		t.Fatal("node \"no-address-yet\" not found")
	}
	ep, ok := noAddr.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	if ep.Address != nil {
		t.Fatalf("expected nil address, got %v", *ep.Address)
	}
	if _, err := ep.ResolveRemote(t.Context()); err == nil {
		t.Fatal("expected ResolveRemote to fail for a nil address")
	}

	// address: "" (empty string, distinct from null) must also fail
	// gracefully rather than being treated as a valid target.
	emptyAddr, ok := org.FindNode("empty-address")
	if !ok {
		t.Fatal("node \"empty-address\" not found")
	}
	ep, ok = emptyAddr.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	if ep.Address == nil || *ep.Address != "" {
		t.Fatalf("expected empty-string address, got %v", ep.Address)
	}
	if _, err := ep.ResolveRemote(t.Context()); err == nil {
		t.Fatal("expected ResolveRemote to fail for an empty-string address")
	}

	// A hostname address; just confirm the field parsed correctly — DNS
	// resolution success/failure is environment-dependent and not what
	// this parser test should assert on.
	gw, ok := org.FindNode("gateway")
	if !ok {
		t.Fatal("node \"gateway\" not found")
	}
	ep, ok = gw.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	if ep.Address == nil || *ep.Address != "gateway.example.invalid" {
		t.Fatalf("unexpected address: %v", ep.Address)
	}
	if ep.AddressFamily != "ip4" || ep.Port != 13000 {
		t.Fatalf("unexpected endpoint: %+v", ep)
	}

	// Non-sequential serial numbers (e.g. "4"/"6" instead of "0"/"1") are
	// used by some real deployments — confirm lookup isn't assuming 0/1.
	nonSeq, ok := org.FindNode("non-sequential-serials")
	if !ok {
		t.Fatal("node \"non-sequential-serials\" not found")
	}
	if _, ok := nonSeq.FindEndpoint("4"); !ok {
		t.Fatal("endpoint serial 4 not found")
	}
	if _, ok := nonSeq.FindEndpoint("6"); !ok {
		t.Fatal("endpoint serial 6 not found")
	}

	// A literal (non-hostname) address should resolve directly without DNS.
	other, ok := reg.FindOrganization("other-org")
	if !ok {
		t.Fatal("organization \"other-org\" not found")
	}
	lit, ok := other.FindNode("literal-address")
	if !ok {
		t.Fatal("node \"literal-address\" not found")
	}
	ep, ok = lit.FindEndpoint("0")
	if !ok {
		t.Fatal("endpoint serial 0 not found")
	}
	ip, err := ep.ResolveRemote(t.Context())
	if err != nil {
		t.Fatalf("ResolveRemote: %v", err)
	}
	if ip.String() != "192.0.2.1" {
		t.Fatalf("got %v, want 192.0.2.1", ip)
	}
}

func TestFindNodeContinuesAcrossDuplicateOrganizations(t *testing.T) {
	reg, err := Load("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	first := reg[0]
	left, right := first, first
	left.Nodes = first.Nodes[:2]
	right.Nodes = first.Nodes[2:]
	right.PublicKey = reg[1].PublicKey
	duplicate := Registry{left, right}
	if err := duplicate.Validate(); err != nil {
		t.Fatal(err)
	}
	organization, node, ok := duplicate.FindNode(first.Organization, first.Nodes[3].CommonName)
	if !ok || node.CommonName != first.Nodes[3].CommonName || organization.PublicKey != right.PublicKey {
		t.Fatalf("FindNode did not continue to the second organization block: %+v, %+v, %v", organization, node, ok)
	}
}

// Resolution has to be cancellable, because Client.Run waits for every dialer
// before it returns and a dialer resolving a hostname whose resolver is
// unreachable would otherwise hold SIGTERM for the resolver's own timeout.
// Dialable decides without a resolver, so it has to refuse only what no
// attempt could fix. A literal the resolver would take, including one carrying
// a zone, is an endpoint a dialer must keep.
func TestDialableRefusesOnlyWhatNoAttemptCanFix(t *testing.T) {
	for address, want := range map[string]bool{
		"198.51.100.9":        true,
		"2001:db8::1":         false,
		"fe80::1%en0":         false,
		"gateway.example.com": true,
		"":                    false,
		"2400::/8":            false,
	} {
		endpoint := Endpoint{SerialNumber: "0", AddressFamily: "ip4", Address: &address}
		if address == "2001:db8::1" || address == "fe80::1%en0" {
			endpoint.AddressFamily = "ip6"
			want = true
		}
		if got := endpoint.Dialable(); got != want {
			t.Errorf("Dialable(%q as %s) = %v, want %v", address, endpoint.AddressFamily, got, want)
		}
	}
	if (Endpoint{SerialNumber: "0", AddressFamily: "ip4"}).Dialable() {
		t.Error("an endpoint with no address at all is dialable")
	}
	wrongFamily := "2001:db8::1"
	if (Endpoint{SerialNumber: "0", AddressFamily: "ip4", Address: &wrongFamily}).Dialable() {
		t.Error("a literal of the wrong family is dialable, and no lookup will fix it")
	}
}

func TestResolveRemoteStopsWhenTheContextDoes(t *testing.T) {
	address := "a-name-no-resolver-should-answer.invalid"
	ep := Endpoint{SerialNumber: "0", AddressFamily: "ip4", Address: &address}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	start := time.Now()
	if _, err := ep.ResolveRemote(ctx); err == nil {
		t.Fatal("a canceled lookup reported an address")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("a canceled lookup took %s, so shutdown waits on the resolver", elapsed)
	}
}

// The lookup is narrowed to the family the endpoint declares, so a name that
// has only the other family's records fails at the resolver rather than after
// it, and a dual-stack name costs one query rather than two.
func TestResolverNetworkFollowsTheDeclaredFamily(t *testing.T) {
	for family, want := range map[string]string{
		"ip4": "ip4",
		"ip6": "ip6",
		"":    "ip",
		"ip":  "ip",
	} {
		if got := resolverNetwork(family); got != want {
			t.Errorf("family %q resolves over %q, want %q", family, got, want)
		}
	}
}

// FindNode takes the first match within a block, so a common name that appears
// twice in one block leaves the second node unreachable and says nothing about
// it. An organization split across several blocks is a supported shape, each
// with its own key, which is why the check is per block.
func TestValidateRefusesADuplicateNodeInOneBlock(t *testing.T) {
	reg, err := Load("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	first := reg[0]
	first.Nodes = append(append([]Node(nil), first.Nodes...), first.Nodes[0])
	if err := (Registry{first}).Validate(); err == nil {
		t.Error("a block naming one node twice was accepted, and the second is unreachable")
	}
	// The split shape is still accepted: the same name in two blocks is how
	// an organization is carried across them.
	left, right := reg[0], reg[0]
	left.Nodes, right.Nodes = reg[0].Nodes[:1], reg[0].Nodes[1:]
	if err := (Registry{left, right}).Validate(); err != nil {
		t.Errorf("an organization split across two blocks was refused: %v", err)
	}
	// What the split may not carry is the same name twice. FindNode walks
	// every block of a matching organization and takes the first hit, and it
	// is the trust-root lookup, so two blocks naming one node under different
	// keys leave the order of the array deciding who authenticates.
	left, right = reg[0], reg[0]
	left.Nodes, right.Nodes = reg[0].Nodes[:1], reg[0].Nodes[:1]
	right.PublicKey = reg[1].PublicKey
	if left.PublicKey == right.PublicKey {
		t.Fatal("the fixture's two organizations share a key, so this proves nothing")
	}
	if err := (Registry{left, right}).Validate(); err == nil {
		t.Error("one node carried two public keys across two blocks of one organization was accepted")
	}
}

// DisallowUnknownFields catches a stray field inside the document. A second
// document after it is the residue of a partial write or a bad concatenation.
// Decode reads the first and says nothing about the rest.
// Decode reads the first and says nothing about the rest.
func TestLoadRefusesTrailingData(t *testing.T) {
	good, err := os.ReadFile("testdata/registry.json")
	if err != nil {
		t.Fatal(err)
	}
	// The bracket cases are the concatenation itself rather than a clean
	// append: json.Decoder.More reports whether another element follows in the
	// array or object being parsed, so it answers false on either closing
	// bracket and lets the document behind one through.
	for name, trailing := range map[string]string{
		"a second document":              "\n{\"anything\":\"at all\"}\n",
		"a stray bracket and a document": "]\n{\"anything\":\"at all\"}\n",
		"a stray brace and a document":   "}\n{\"anything\":\"at all\"}\n",
		"a stray bracket":                "]",
	} {
		t.Run(name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "registry.json")
			if err := os.WriteFile(path, append(append([]byte(nil), good...), trailing...), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := Load(path); err == nil {
				t.Errorf("a registry followed by %s was loaded without complaint", name)
			}
		})
	}
	// Trailing whitespace is not trailing data.
	path := filepath.Join(t.TempDir(), "registry.json")
	if err := os.WriteFile(path, append(append([]byte(nil), good...), "\n\n  \n"...), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err != nil {
		t.Errorf("a registry with trailing whitespace was refused: %v", err)
	}
}
