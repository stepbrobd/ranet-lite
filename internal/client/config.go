package client

import (
	"bytes"
	"crypto/ed25519"
	"fmt"

	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/registry"
)

func validateRuntimeConfig(cfg *config.Config, privateKey ed25519.PrivateKey, reg registry.Registry) error {
	organization, localNode, ok := reg.FindNode(cfg.Organization, cfg.CommonName)
	if !ok {
		return fmt.Errorf("config: local node %q not found in organization %q", cfg.CommonName, cfg.Organization)
	}
	publicKey, err := organization.ParsePublicKey()
	if err != nil {
		return err
	}
	if !bytes.Equal(privateKey.Public().(ed25519.PublicKey), publicKey) {
		return fmt.Errorf("config: private key does not match organization %q", cfg.Organization)
	}
	localFamilies := make(map[string]struct{}, len(cfg.Endpoints))
	for _, endpoint := range cfg.Endpoints {
		registered, ok := localNode.FindEndpoint(endpoint.SerialNumber)
		if !ok || registered.AddressFamily != endpoint.AddressFamily {
			return fmt.Errorf("config: local endpoint %q/%s does not match the registry", endpoint.SerialNumber, endpoint.AddressFamily)
		}
		localFamilies[endpoint.AddressFamily] = struct{}{}
	}
	for _, peer := range cfg.Peers {
		_, node, ok := reg.FindNode(peer.Organization, peer.CommonName)
		if !ok {
			return fmt.Errorf("config: peer node %q not found in organization %q", peer.CommonName, peer.Organization)
		}
		if peer.SerialNumber != "" {
			endpoint, ok := node.FindEndpoint(peer.SerialNumber)
			if !ok {
				return fmt.Errorf("config: peer %s/%s endpoint %q not found", peer.Organization, peer.CommonName, peer.SerialNumber)
			}
			if _, ok := localFamilies[endpoint.AddressFamily]; !ok {
				return fmt.Errorf("config: peer endpoint %s/%s/%s has no matching local address family", peer.Organization, peer.CommonName, peer.SerialNumber)
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
			return fmt.Errorf("config: peer %s/%s has no endpoint matching a local address family", peer.Organization, peer.CommonName)
		}
	}
	return nil
}
