package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"net/netip"
	"slices"
	"strings"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/registry"
	"github.com/NickCao/ranet-lite/internal/srv6"
)

// validateRuntimeConfig refuses a configuration the registry does not support.
// It is the startup check: nothing is running and nobody is relying on this
// node yet, so a peer that cannot be resolved is a mistake worth stopping for.
// A peer the registry names but this node cannot dial is not such a mistake
// and is logged instead, see validatePeers. A reload checks the two halves
// separately, see Reload.
func validateRuntimeConfig(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry) error {
	families, err := validateLocalConfig(cfg, privateKey, reg)
	if err != nil {
		return err
	}
	refuse, skip := validatePeers(cfg, reg, families)
	for _, problem := range skip {
		log.Printf("%v, so nothing will dial it", problem)
	}
	return errors.Join(refuse...)
}

// validateLocalConfig checks what this node says about itself, and reports the
// address families its own endpoints cover. Every one of these is fatal on a
// reload too: a node the registry no longer names, or whose key no longer
// matches its organization, is not a node that should carry on with a new
// registry.
func validateLocalConfig(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry) (map[string]struct{}, error) {
	organization, localNode, ok := reg.FindNode(cfg.Organization, cfg.CommonName)
	if !ok {
		return nil, fmt.Errorf("config: local node %q not found in organization %q", cfg.CommonName, cfg.Organization)
	}
	publicKey, err := organization.ParsePublicKey()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return nil, fmt.Errorf("config: private key does not match organization %q", cfg.Organization)
	}
	localFamilies := make(map[string]struct{}, len(cfg.Endpoints))
	for _, endpoint := range cfg.Endpoints {
		registered, ok := localNode.FindEndpoint(endpoint.SerialNumber)
		if !ok || registered.AddressFamily != endpoint.AddressFamily {
			return nil, fmt.Errorf("config: local endpoint %q/%s does not match the registry", endpoint.SerialNumber, endpoint.AddressFamily)
		}
		localFamilies[endpoint.AddressFamily] = struct{}{}
	}
	return localFamilies, nil
}

// localSegments builds the table this node answers segment routing with, and
// refuses a configuration it cannot. It is here rather than in internal/srv6
// because that package takes bytes and returns bytes, and a config file is
// neither.
func localSegments(cfg *config.Config) (*srv6.LocalTable, error) {
	if len(cfg.Segments.Local) == 0 {
		return nil, nil
	}
	segments := make([]srv6.Segment, 0, len(cfg.Segments.Local))
	for _, local := range cfg.Segments.Local {
		sid, err := netip.ParseAddr(local.SID)
		if err != nil {
			return nil, fmt.Errorf("config: segments.local sid %q: %w", local.SID, err)
		}
		behavior, err := srv6.ParseBehavior(local.Behavior)
		if err != nil {
			return nil, fmt.Errorf("config: segments.local %s: %w", local.SID, err)
		}
		segments = append(segments, srv6.Segment{SID: sid, Behavior: behavior})
	}
	return srv6.NewLocalTable(segments)
}

// steerTable builds the table deciding which of this node's own packets go
// through a segment list.
func steerTable(cfg *config.Config) (*srv6.SteerTable, error) {
	if len(cfg.Segments.Steer) == 0 {
		return nil, nil
	}
	entries := make([]srv6.Steer, 0, len(cfg.Segments.Steer))
	for _, entry := range cfg.Segments.Steer {
		from, err := steerPrefix("from", entry.From)
		if err != nil {
			return nil, err
		}
		to, err := steerPrefix("to", entry.To)
		if err != nil {
			return nil, err
		}
		raw := entry.Source
		if raw == "" {
			raw = cfg.Segments.Source
		}
		if raw == "" {
			return nil, fmt.Errorf("config: segments.steer %q needs a source, either its own or segments.source", entry.Via)
		}
		source, err := netip.ParseAddr(raw)
		if err != nil {
			return nil, fmt.Errorf("config: segments source %q: %w", raw, err)
		}
		path := make([]netip.Addr, 0, len(entry.Via))
		for _, hop := range entry.Via {
			segment, err := netip.ParseAddr(hop)
			if err != nil {
				return nil, fmt.Errorf("config: segments.steer via %q: %w", hop, err)
			}
			path = append(path, segment)
		}
		entries = append(entries, srv6.Steer{From: from, To: to, Policy: srv6.Policy{Source: source, Path: path}})
	}
	return srv6.NewSteerTable(entries)
}

func steerPrefix(name, raw string) (netip.Prefix, error) {
	if raw == "" {
		return netip.Prefix{}, nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("config: segments.steer %s %q: %w", name, raw, err)
	}
	return prefix.Masked(), nil
}

// effectivePeers is who this node dials: the configured list, or every node
// the registry names when full_mesh is set, which is the N-to-N reconciliation
// ranet does, with the configured entries kept ahead of the generated ones.
// This node itself is never in it. Registry order is kept, so the same pair of
// files produces the same order on every start.
func effectivePeers(cfg *config.Config, reg registry.Registry) []config.Peer {
	if !cfg.FullMesh {
		return cfg.Peers
	}
	named := make(map[string]struct{}, len(cfg.Peers))
	for _, peer := range cfg.Peers {
		named[peer.Organization+"\x00"+peer.CommonName] = struct{}{}
	}
	peers := slices.Clone(cfg.Peers)
	for _, org := range reg {
		for _, node := range org.Nodes {
			if org.Organization == cfg.Organization && node.CommonName == cfg.CommonName {
				continue
			}
			// An explicit entry wins for its node: it can pin a
			// serial_number, and a generated one names none, so generating a
			// second entry for the same node would dial both endpoints.
			if _, ok := named[org.Organization+"\x00"+node.CommonName]; ok {
				continue
			}
			peers = append(peers, config.Peer{Organization: org.Organization, CommonName: node.CommonName})
		}
	}
	return peers
}

// validatePeers reports one error per peer the registry cannot support, split
// into what a startup refuses and what it only logs. They are returned rather
// than raised because a reload treats both as advisory, see Reload.
//
// The split matters for a single-stack node. A community registry holds nodes
// reachable over one address family only, so a v4-only host finds peers it can
// never dial however correct its own configuration is, and refusing to start
// over them leaves that host with no way to run at all. runPeer already ends
// the dialer for exactly this case. A peer the registry does not name, or one
// whose named endpoint is missing or of the wrong family, stays fatal: each of
// those is somebody having written the wrong thing down.
func validatePeers(cfg *config.Config, reg registry.Registry, localFamilies map[string]struct{}) (refuse, skip []error) {
	for _, peer := range effectivePeers(cfg, reg) {
		_, node, ok := reg.FindNode(peer.Organization, peer.CommonName)
		if !ok {
			refuse = append(refuse, fmt.Errorf("config: peer node %q not found in organization %q", peer.CommonName, peer.Organization))
			continue
		}
		if peer.SerialNumber != "" {
			endpoint, ok := node.FindEndpoint(peer.SerialNumber)
			if !ok {
				refuse = append(refuse, fmt.Errorf("config: peer %s/%s endpoint %q not found", peer.Organization, peer.CommonName, peer.SerialNumber))
				continue
			}
			if _, ok := localFamilies[endpoint.AddressFamily]; !ok {
				refuse = append(refuse, fmt.Errorf("config: peer endpoint %s/%s/%s has no matching local address family", peer.Organization, peer.CommonName, peer.SerialNumber))
				continue
			}
			if !endpoint.Dialable() {
				skip = append(skip, fmt.Errorf("config: peer endpoint %s/%s/%s carries no address", peer.Organization, peer.CommonName, peer.SerialNumber))
			}
			continue
		}
		// Dialable is part of the question, not a refinement of it: an
		// endpoint the dialer will not take is reported here, once, rather
		// than by the dialer on every attempt.
		compatible, reachable := false, false
		for _, endpoint := range node.Endpoints {
			if _, ok := localFamilies[endpoint.AddressFamily]; !ok {
				continue
			}
			compatible = true
			if endpoint.Dialable() {
				reachable = true
				break
			}
		}
		switch {
		case !compatible:
			skip = append(skip, fmt.Errorf("config: peer %s/%s has no endpoint matching a local address family", peer.Organization, peer.CommonName))
		case !reachable:
			skip = append(skip, fmt.Errorf("config: peer %s/%s has no endpoint carrying an address", peer.Organization, peer.CommonName))
		}
	}
	return refuse, skip
}

// warnUnforwardableTransit says so when this node offers to carry the mesh and
// the kernel will not.
//
// Babel carries no capability signal: a node that advertises a route is
// promising to forward it, and the only thing a peer ever learns is the
// advertisement. So a node that redistributes with forwarding off attracts
// traffic and drops it, and the sender is never told. Nothing here can fix
// that from the far end, which leaves saying it at the end that knows.
//
// A warning rather than a refusal, because forwarding can be turned on after
// this process starts and because babel.no_transit is the setting that makes
// the promise match the machine.
func warnUnforwardableTransit(cfg *config.Config) {
	if cfg.Babel.NoTransit {
		return
	}
	v4, v6 := forwardingEnabled()
	if v4 && v6 {
		return
	}
	var off []string
	if !v4 {
		off = append(off, "IPv4")
	}
	if !v6 {
		off = append(off, "IPv6")
	}
	log.Printf("config: this node redistributes the routes it learns, so it is offering to carry the mesh, but %s forwarding is off: peers that select it will have their traffic dropped with nothing to tell them. Set babel.no_transit on a leaf, or turn forwarding on",
		strings.Join(off, " and "))
}
