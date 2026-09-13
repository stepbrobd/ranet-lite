package main

import (
	"net/netip"
	"slices"
	"testing"

	"github.com/NickCao/ranet-lite/internal/config"
)

func TestKernelConfigAddresses(t *testing.T) {
	explicit := netip.MustParsePrefix("192.0.2.7/24")
	topLevel := netip.MustParsePrefix("2001:db8:1::7/64")
	plain := netip.MustParsePrefix("2001:db8:2::7/64")
	sourceSpecific := netip.MustParsePrefix("2001:db8:3::7/64")
	for _, test := range []struct {
		name             string
		assignOriginated bool
		want             []netip.Prefix
	}{
		{
			name:             "assigns every originated prefix, source-specific ones included",
			assignOriginated: true,
			want:             []netip.Prefix{explicit, topLevel, plain, sourceSpecific},
		},
		{
			name: "retains only explicit addresses when assignment is disabled",
			want: []netip.Prefix{explicit},
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &config.Config{
				Kernel: config.Kernel{
					Addresses:        []string{explicit.String(), explicit.String()},
					AssignOriginated: test.assignOriginated,
				},
				Originate: []string{explicit.String(), topLevel.String()},
				Babel: config.Babel{Originate: []config.OriginatePrefix{
					{Prefix: topLevel},
					{Prefix: plain},
					{Prefix: sourceSpecific, From: netip.MustParsePrefix("2001:db8:4::/64")},
					{Prefix: sourceSpecific, From: netip.MustParsePrefix("2001:db8:5::/64")},
				}},
			}
			got, err := kernelConfig(cfg, "ranet0")
			if err != nil {
				t.Fatal(err)
			}
			if !slices.Equal(got.Addresses, test.want) {
				t.Fatalf("assigned addresses = %v, want %v", got.Addresses, test.want)
			}
		})
	}
}
