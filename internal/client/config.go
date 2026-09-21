package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"
	"log"
	"slices"
	"strings"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/registry"
)

// validateRuntimeConfig refuses a configuration the trust document does not
// support. It is the startup check: nothing is running and nobody is relying
// on this node yet, so a peer that cannot be resolved is a mistake worth
// stopping for. A peer the document names but this node cannot dial is not
// such a mistake and is logged instead, see validatePeers. A reload checks the
// two halves separately, see Reload.
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
// reload too: a node the trust document no longer names, or whose key no
// longer matches its organization, is not a node that should carry on with a
// new one.
func validateLocalConfig(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry) (map[string]struct{}, error) {
	organization, localNode, ok := reg.FindNode(cfg.Node.Org, cfg.Node.Name)
	if !ok {
		return nil, fmt.Errorf("config: node %q not found in organization %q", cfg.Node.Name, cfg.Node.Org)
	}
	publicKey, err := organization.ParsePublicKey()
	if err != nil {
		return nil, err
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return nil, fmt.Errorf("config: auth.key does not match organization %q", cfg.Node.Org)
	}
	localFamilies := make(map[string]struct{}, len(cfg.Link.Endpoints))
	for _, endpoint := range cfg.Link.Endpoints {
		registered, ok := localNode.FindEndpoint(endpoint.Serial)
		if !ok || registered.AddressFamily != endpoint.Family {
			return nil, fmt.Errorf("config: link.endpoints %q/%s does not match the trust document", endpoint.Serial, endpoint.Family)
		}
		localFamilies[endpoint.Family] = struct{}{}
	}
	return localFamilies, nil
}

// effectivePeers is who this node dials: the configured list, or every node
// the trust document names when dial.all is set, which is the N-to-N
// reconciliation ranet does, with the configured entries kept ahead of the
// generated ones. This node itself is never in it. Registry order is kept, so
// the same pair of files produces the same order on every start.
func effectivePeers(cfg *config.Config, reg registry.Registry) []config.Peer {
	if !cfg.Dial.All {
		return cfg.Dial.To
	}
	named := make(map[string]struct{}, len(cfg.Dial.To))
	for _, peer := range cfg.Dial.To {
		named[peer.Org+"\x00"+peer.Name] = struct{}{}
	}
	peers := slices.Clone(cfg.Dial.To)
	for _, org := range reg {
		for _, node := range org.Nodes {
			if org.Organization == cfg.Node.Org && node.CommonName == cfg.Node.Name {
				continue
			}
			// An explicit entry wins for its node: it can pin a serial, and a
			// generated one names none, so generating a second entry for the
			// same node would dial both endpoints.
			if _, ok := named[org.Organization+"\x00"+node.CommonName]; ok {
				continue
			}
			peers = append(peers, config.Peer{Org: org.Organization, Name: node.CommonName})
		}
	}
	return peers
}

// validatePeers reports one error per peer the trust document cannot support,
// split into what a startup refuses and what it only logs. They are returned
// rather than raised because a reload treats both as advisory, see Reload.
//
// The split matters for a single-stack node. A community document holds nodes
// reachable over one address family only, so a v4-only host finds peers it can
// never dial however correct its own configuration is, and refusing to start
// over them leaves that host with no way to run at all. runPeer already ends
// the dialer for exactly this case. A peer the document does not name, or one
// whose named endpoint is missing or of the wrong family, stays fatal: each of
// those is somebody having written the wrong thing down.
func validatePeers(cfg *config.Config, reg registry.Registry, localFamilies map[string]struct{}) (refuse, skip []error) {
	for _, peer := range effectivePeers(cfg, reg) {
		_, node, ok := reg.FindNode(peer.Org, peer.Name)
		if !ok {
			refuse = append(refuse, fmt.Errorf("config: peer node %q not found in organization %q", peer.Name, peer.Org))
			continue
		}
		if peer.Serial != "" {
			endpoint, ok := node.FindEndpoint(peer.Serial)
			if !ok {
				refuse = append(refuse, fmt.Errorf("config: peer %s/%s endpoint %q not found", peer.Org, peer.Name, peer.Serial))
				continue
			}
			if _, ok := localFamilies[endpoint.AddressFamily]; !ok {
				refuse = append(refuse, fmt.Errorf("config: peer endpoint %s/%s/%s has no matching local address family", peer.Org, peer.Name, peer.Serial))
				continue
			}
			if !endpoint.Dialable() {
				skip = append(skip, fmt.Errorf("config: peer endpoint %s/%s/%s carries no address", peer.Org, peer.Name, peer.Serial))
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
			skip = append(skip, fmt.Errorf("config: peer %s/%s has no endpoint matching a local address family", peer.Org, peer.Name))
		case !reachable:
			skip = append(skip, fmt.Errorf("config: peer %s/%s has no endpoint carrying an address", peer.Org, peer.Name))
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
	if cfg.Cap.Table == nil || cfg.Cap.Table.Name() == "" || l3mdevAccept() {
		return
	}
	log.Printf("config: the mesh is in vrf %s and net.ipv4.tcp_l3mdev_accept or net.ipv4.udp_l3mdev_accept is off, so a socket outside that vrf will not be matched by a reply arriving through it: every TCP and UDP flow to and from a mesh address fails while ping answers. Set both to 1, or run the services that use the mesh inside the vrf",
		cfg.Cap.Table.Name())
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
// this process starts and because cap.route transit is the setting that makes
// the promise match the machine.
func warnUnforwardableTransit(cfg *config.Config) {
	if !cfg.Routes().Transits() {
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
	log.Printf("config: this node redistributes the routes it learns, so it is offering to carry the mesh, but %s forwarding is off: peers that select it will have their traffic dropped with nothing to tell them. Write transit = false under cap.route on a leaf, or turn forwarding on",
		strings.Join(off, " and "))
}
