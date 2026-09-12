package client

import (
	"bytes"
	"crypto/ed25519"
	"errors"
	"fmt"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/registry"
)

// validateRuntimeConfig refuses a configuration the registry does not support.
// It is the startup check: nothing is running and nobody is relying on this
// node yet, so a peer that cannot be resolved is a mistake worth stopping for.
// A reload checks the two halves separately, see Reload.
func validateRuntimeConfig(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry) error {
	families, err := validateLocalConfig(cfg, privateKey, reg)
	if err != nil {
		return err
	}
	return errors.Join(validatePeers(cfg, reg, families)...)
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

// validatePeers reports one error per peer the registry cannot support. They
// are returned rather than raised because a reload treats them as advisory,
// see Reload.
func validatePeers(cfg *config.Config, reg registry.Registry, localFamilies map[string]struct{}) []error {
	var problems []error
	for _, peer := range cfg.Peers {
		_, node, ok := reg.FindNode(peer.Organization, peer.CommonName)
		if !ok {
			problems = append(problems, fmt.Errorf("config: peer node %q not found in organization %q", peer.CommonName, peer.Organization))
			continue
		}
		if peer.SerialNumber != "" {
			endpoint, ok := node.FindEndpoint(peer.SerialNumber)
			if !ok {
				problems = append(problems, fmt.Errorf("config: peer %s/%s endpoint %q not found", peer.Organization, peer.CommonName, peer.SerialNumber))
				continue
			}
			if _, ok := localFamilies[endpoint.AddressFamily]; !ok {
				problems = append(problems, fmt.Errorf("config: peer endpoint %s/%s/%s has no matching local address family", peer.Organization, peer.CommonName, peer.SerialNumber))
			}
			continue
		}
		compatible := false
		for _, endpoint := range node.Endpoints {
			if _, ok := localFamilies[endpoint.AddressFamily]; ok {
				compatible = true
				break
			}
		}
		if !compatible {
			problems = append(problems, fmt.Errorf("config: peer %s/%s has no endpoint matching a local address family", peer.Organization, peer.CommonName))
		}
	}
	return problems
}
