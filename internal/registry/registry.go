// Package registry reads ranet's own registry and key file formats
// unchanged, so a ranet-lite deployment can point at the exact same
// registry.json and Ed25519 keys an existing ranet mesh already uses.
// Schema mirrors github.com/NickCao/ranet's src/registry.rs field for
// field (verified against its own test fixture, not guessed).
package registry

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"strings"
)

type Registry []Organization

type Organization struct {
	PublicKey    string `json:"public_key"` // PEM SubjectPublicKeyInfo, one Ed25519 key shared by every node in the org
	Organization string `json:"organization"`
	Nodes        []Node `json:"nodes"`
}

type Node struct {
	CommonName string          `json:"common_name"`
	Endpoints  []Endpoint      `json:"endpoints"`
	Remarks    json.RawMessage `json:"remarks"`
}

type Endpoint struct {
	SerialNumber  string  `json:"serial_number"`
	AddressFamily string  `json:"address_family"` // "ip4" or "ip6"
	Address       *string `json:"address"`        // literal IP, hostname, or absent (wildcard)
	Port          uint16  `json:"port"`
}

func Load(path string) (Registry, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("registry: read %s: %w", path, err)
	}
	var r Registry
	decoder := json.NewDecoder(bytes.NewReader(b))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&r); err != nil {
		return nil, fmt.Errorf("registry: parse %s: %w", path, err)
	}
	// DisallowUnknownFields catches a stray field inside the document; this
	// catches a second document after it, which a partial write or a bad
	// concatenation leaves behind and which Decode would otherwise ignore
	// entirely. Token rather than More: More answers "is there another element
	// in the array or object being parsed" and so reports false on a stray "]"
	// or "}", which is one character of the concatenation this is here to
	// refuse. Only an exhausted reader gives io.EOF, and trailing whitespace
	// still does.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("registry: parse %s: trailing data after the registry", path)
	}
	return r, r.Validate()
}

func (r Registry) Validate() error {
	// FindNode takes the first match and walks every block whose organization
	// name matches, so a common name has to be unique across all of them and
	// not merely within one block. Two blocks named alike, each carrying a
	// node "a" with a different public key, would otherwise both validate and
	// leave the order of the array to decide which key authenticates that
	// peer, which is the trust-root lookup. Splitting an organization across
	// blocks stays supported; only a name collision within one does not.
	nodes := make(map[string]map[string]struct{}, len(r))
	for _, organization := range r {
		if organization.Organization == "" {
			return fmt.Errorf("registry: organization name is required")
		}
		if _, err := organization.ParsePublicKey(); err != nil {
			return err
		}
		named := nodes[organization.Organization]
		if named == nil {
			named = make(map[string]struct{}, len(organization.Nodes))
			nodes[organization.Organization] = named
		}
		for _, node := range organization.Nodes {
			if node.CommonName == "" {
				return fmt.Errorf("registry: organization %q has a node without common_name", organization.Organization)
			}
			if _, exists := named[node.CommonName]; exists {
				return fmt.Errorf("registry: duplicate node %q in organization %q", node.CommonName, organization.Organization)
			}
			named[node.CommonName] = struct{}{}
			endpoints := make(map[string]struct{}, len(node.Endpoints))
			for _, endpoint := range node.Endpoints {
				if endpoint.SerialNumber == "" || endpoint.Port == 0 || (endpoint.AddressFamily != "ip4" && endpoint.AddressFamily != "ip6") {
					return fmt.Errorf("registry: node %q has an invalid endpoint", node.CommonName)
				}
				if _, exists := endpoints[endpoint.SerialNumber]; exists {
					return fmt.Errorf("registry: duplicate endpoint %q on node %q", endpoint.SerialNumber, node.CommonName)
				}
				endpoints[endpoint.SerialNumber] = struct{}{}
			}
		}
	}
	return nil
}

// ParsePublicKey parses the organization's shared Ed25519 SubjectPublicKeyInfo PEM.
func (o Organization) ParsePublicKey() (ed25519.PublicKey, error) {
	blk, _ := pem.Decode([]byte(o.PublicKey))
	if blk == nil {
		return nil, fmt.Errorf("registry: organization %q: no PEM block in public_key", o.Organization)
	}
	pub, err := x509.ParsePKIXPublicKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("registry: organization %q: parse public key: %w", o.Organization, err)
	}
	ed, ok := pub.(ed25519.PublicKey)
	if !ok {
		return nil, fmt.Errorf("registry: organization %q: public key is not Ed25519", o.Organization)
	}
	return ed, nil
}

// FindOrganization returns the named organization, if present.
func (r Registry) FindOrganization(name string) (Organization, bool) {
	for _, o := range r {
		if o.Organization == name {
			return o, true
		}
	}
	return Organization{}, false
}

// FindNode scans every matching organization block and returns the first
// matching node. Organization names are not required to be unique.
func (r Registry) FindNode(organization, commonName string) (Organization, Node, bool) {
	for _, candidate := range r {
		if candidate.Organization != organization {
			continue
		}
		if node, ok := candidate.FindNode(commonName); ok {
			return candidate, node, true
		}
	}
	return Organization{}, Node{}, false
}

// FindNode returns the named node within organization, if present.
func (o Organization) FindNode(commonName string) (Node, bool) {
	for _, n := range o.Nodes {
		if n.CommonName == commonName {
			return n, true
		}
	}
	return Node{}, false
}

// FindEndpoint returns the endpoint with the given serial number, if present.
func (n Node) FindEndpoint(serial string) (Endpoint, bool) {
	for _, e := range n.Endpoints {
		if e.SerialNumber == serial {
			return e, true
		}
	}
	return Endpoint{}, false
}

// ResolveRemote resolves an endpoint's address for dialing, mirroring
// ranet's src/address.rs `remote`: a literal IP is used directly; a
// hostname is resolved via DNS and filtered to the endpoint's declared
// address family; if that fails, ranet falls back to the address family's
// wildcard, which isn't a dialable address — callers must treat a failure
// here as "endpoint not currently reachable", not retry with a wildcard.
//
// The context makes shutdown prompt: a hostname whose resolver is
// unreachable otherwise holds the dialer for the resolver's own timeout, and
// the client waits for every dialer before it returns.
func (e Endpoint) ResolveRemote(ctx context.Context) (net.IP, error) {
	if e.Address == nil {
		return nil, fmt.Errorf("registry: endpoint %s has no address", e.SerialNumber)
	}
	if ip := net.ParseIP(*e.Address); ip != nil {
		if !addressFamilyMatches(e.AddressFamily, ip) {
			return nil, fmt.Errorf("registry: endpoint %s address %s does not match declared family %s", e.SerialNumber, *e.Address, e.AddressFamily)
		}
		return ip, nil
	}
	ips, err := net.DefaultResolver.LookupIP(ctx, resolverNetwork(e.AddressFamily), *e.Address)
	if err != nil {
		return nil, fmt.Errorf("registry: resolve %s: %w", *e.Address, err)
	}
	for _, ip := range ips {
		if addressFamilyMatches(e.AddressFamily, ip) {
			return ip, nil
		}
	}
	return nil, fmt.Errorf("registry: %s has no %s address", *e.Address, e.AddressFamily)
}

// resolverNetwork narrows the lookup to the family this endpoint declares, so
// a name with only the other family's records fails at the resolver rather
// than after it.
func resolverNetwork(family string) string {
	switch family {
	case "ip4":
		return "ip4"
	case "ip6":
		return "ip6"
	default:
		return "ip"
	}
}

// Dialable reports whether this endpoint could ever be reached, deciding it
// without a resolver, so that a dialer is never started for one no attempt can
// fix. On the community registry 94 of 139 peers carry no address at all, and
// among the rest are an empty string and an address written as a prefix.
//
// A name is taken on trust, because only a resolver can answer for one and its
// answer changes. A literal is not: an address of the wrong family is a
// mistake in the registry that no lookup will fix.
func (e Endpoint) Dialable() bool {
	if e.Address == nil || *e.Address == "" {
		return false
	}
	if address, err := netip.ParseAddr(*e.Address); err == nil {
		// netip rather than net.ParseIP, which refuses a zone: a link-local
		// with one is a literal the resolver takes, so refusing it here would
		// give up on an endpoint a dial can use.
		return addressFamilyMatches(e.AddressFamily, address.WithZone("").AsSlice())
	}
	return !strings.ContainsAny(*e.Address, ":/ ")
}

func addressFamilyMatches(family string, ip net.IP) bool {
	switch family {
	case "ip4":
		return ip.To4() != nil
	case "ip6":
		return ip.To4() == nil
	default:
		return false
	}
}
