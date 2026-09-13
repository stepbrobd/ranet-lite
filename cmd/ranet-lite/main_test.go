package main

import (
	"context"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"testing"
	"time"

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

// The first signal starts the shutdown and the second gives up on it. An
// earlier shape registered the second channel only after the first signal had
// cancelled the context, which left a window where a signal reached nobody:
// two with no gap lost the second and the process sat through the whole
// shutdown. Registering up front instead delivered the first signal to both
// readers, so the first Ctrl-C forced an exit rather than shutting down. One
// channel read in order has neither, and a burst is held by the buffer.
func TestTheFirstSignalShutsDownAndTheSecondGivesUp(t *testing.T) {
	for name, gap := range map[string]bool{"a burst of two": false, "one then another": true} {
		t.Run(name, func(t *testing.T) {
			signals := make(chan os.Signal, 2)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			forced := make(chan struct{})
			go watchSignals(signals, cancel, func() { close(forced) })

			signals <- os.Interrupt
			if gap {
				select {
				case <-ctx.Done():
				case <-time.After(5 * time.Second):
					t.Fatal("the first signal did not start the shutdown")
				}
				select {
				case <-forced:
					t.Fatal("the first signal gave up on the shutdown instead of starting it")
				case <-time.After(50 * time.Millisecond):
				}
			}
			signals <- os.Interrupt
			select {
			case <-forced:
			case <-time.After(5 * time.Second):
				t.Fatal("the second signal was lost, so the shutdown runs to completion with nothing to interrupt it")
			}
			if ctx.Err() == nil {
				t.Error("the shutdown was never started")
			}
		})
	}
}

// `ranet-lite config.yaml`, one missing dash, otherwise starts against the
// default path and reports nothing: the node comes up with a configuration
// nobody asked for. An unreadable -log-level is the same shape.
func TestTheCommandLineRefusesWhatItCannotActOn(t *testing.T) {
	for name, args := range map[string][]string{
		"a positional argument": {"config.yaml"},
		"one after a flag":      {"-config", "/etc/x.yaml", "extra"},
		"an unreadable level":   {"-log-level", "chatty"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := parseOptions(args, io.Discard); err == nil {
				t.Errorf("parseOptions(%q) was accepted", args)
			}
		})
	}
	opts, err := parseOptions([]string{"-config", "/etc/x.yaml", "-log-level", "debug"}, io.Discard)
	if err != nil {
		t.Fatalf("a well-formed command line was refused: %v", err)
	}
	if opts.configPath != "/etc/x.yaml" || opts.level != slog.LevelDebug {
		t.Errorf("parsed %+v, want the config path and level given", opts)
	}
}
