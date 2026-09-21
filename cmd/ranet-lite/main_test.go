package main

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"
)

// The first signal starts the shutdown and the second gives up on it. An
// earlier shape registered the second channel only after the first signal had
// canceled the context, which left a window where a signal reached nobody:
// two with no gap lost the second and the process sat through the whole
// shutdown. Registering up front instead delivered the first signal to both
// readers, so the first Ctrl-C forced an exit rather than shutting down. One
// channel read in order has neither, and a burst is held by the buffer.
func TestFirstSignalShutsDownAndTheSecondGivesUp(t *testing.T) {
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

// `ranet-lite daemon config.yaml`, one missing dash, otherwise starts against
// the default path and reports nothing: the node comes up with a
// configuration nobody asked for. An unreadable --log-level is the same shape.
func TestDaemonRefusesWhatItCannotActOn(t *testing.T) {
	for name, args := range map[string][]string{
		"a positional argument": {"daemon", "config.yaml"},
		"one after a flag":      {"daemon", "--config", "/etc/x.yaml", "extra"},
		"an unreadable level":   {"daemon", "--log-level", "chatty"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := execute(t, args...); err == nil {
				t.Errorf("%q was accepted", args)
			}
		})
	}

	// --help is a request cobra answers by writing the usage. Reported as a
	// failure it exits nonzero on a question that was answered.
	usage, err := execute(t, "daemon", "--help")
	if err != nil {
		t.Errorf("asking for help failed: %v", err)
	}
	for _, want := range []string{"--config", "--log-level", "--metrics"} {
		if !strings.Contains(usage, want) {
			t.Errorf("the usage does not name %s: %q", want, usage)
		}
	}
}

// log.Fatal is os.Exit, which a test cannot observe, so this reads the source.
// The helper existing is not the fix: a call site that still reports through
// the standard logger exits 1 saying nothing at a production level.
func TestStartupRefusalsAvoidTheStandardLogger(t *testing.T) {
	body, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(body, []byte("log.Fatal")) {
		t.Error("main.go still exits through log.Fatal, which writes at INFO and vanishes at --log-level warn")
	}
}

// The same rule from the other side: a refusal at --log-level error is written.
// See refuseToStart.
func TestStartupRefusalsSurviveAProductionLogLevel(t *testing.T) {
	var written strings.Builder
	previous := slog.Default()
	t.Cleanup(func() { slog.SetDefault(previous) })
	slog.SetDefault(slog.New(slog.NewTextHandler(&written, &slog.HandlerOptions{Level: slog.LevelError})))

	if code := refuseToStart(errors.New("config: read /nonexistent.yaml")); code == 0 {
		t.Error("a refusal reported success")
	}
	if !strings.Contains(written.String(), "/nonexistent.yaml") {
		t.Errorf("a refusal at --log-level error wrote %q", written.String())
	}
}
