package client

import (
	"bytes"
	"cmp"
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
	if err := refuseSegmentOnOwnAddress(cfg, segments); err != nil {
		return nil, err
	}
	return srv6.NewLocalTable(segments)
}

// refuseSegmentOnOwnAddress rejects a SID this node also carries as an
// ordinary address. The inbound seam acts on a packet by its destination
// before the tun sees it, so every packet to that address would be refused as
// carrying no routing header, and the address would go dark with nothing but a
// rate-limited warning to say why. On linux the two coexist because the SID is
// a route rather than an address. Here they cannot.
//
// The set covers everything the reconciler assigns rather than
// kernel.addresses alone, since assign_originated puts every originated
// prefix on the device too.
func refuseSegmentOnOwnAddress(cfg *config.Config, segments []srv6.Segment) error {
	assigned, err := cfg.KernelAddresses()
	if err != nil {
		return err
	}
	carried := make(map[netip.Addr]bool, len(assigned))
	for _, prefix := range assigned {
		carried[prefix.Addr()] = true
	}
	for _, segment := range segments {
		if carried[segment.SID] {
			return fmt.Errorf("config: segments.local %s is an address this node assigns to its own device, so every packet to it would be taken as a segment", segment.SID)
		}
	}
	return nil
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
		raw := cmp.Or(entry.Source, cfg.Segments.Source)
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
	// Refused rather than masked, as kernel.Rule.validate refuses the same
	// typo. Masking a host address written with the wrong length steers a
	// whole prefix where one address was meant, and says nothing.
	if prefix.Masked() != prefix {
		return netip.Prefix{}, fmt.Errorf("config: segments.steer %s %s has bits set below its prefix length", name, prefix)
	}
	return prefix, nil
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

// warnVRFWithoutL3mdev says so when this node's mesh lives in a VRF and no
// socket outside it will see a reply. See l3mdevAccept for what that costs.
//
// A warning rather than a refusal, as with forwarding: the sysctls can be set
// after this process starts, and a deployment that runs its services inside
// the VRF with "ip vrf exec" needs neither. What it must not be is silent,
// because the mesh comes up correct, the routes are right, and every service
// on the node is unreachable over it.
func warnVRFWithoutL3mdev(cfg *config.Config) {
	if !cfg.Kernel.Enabled || cfg.Kernel.VRF == "" || l3mdevAccept() {
		return
	}
	log.Printf("config: the mesh is in vrf %s and net.ipv4.tcp_l3mdev_accept or net.ipv4.udp_l3mdev_accept is off, so a socket outside that vrf will not be matched by a reply arriving through it: every TCP and UDP flow to and from a mesh address fails while ping answers. Set both to 1, or run the services that use the mesh inside the vrf",
		cfg.Kernel.VRF)
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
