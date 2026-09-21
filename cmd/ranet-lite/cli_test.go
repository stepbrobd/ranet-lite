package main

import (
	"io"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NickCao/ranet-lite/internal/control"
)

// stubSource stands in for a running node, so the subcommands are exercised
// over a real socket without one.
type stubSource struct{}

func (stubSource) Status() control.Status {
	return control.Status{Organization: "example", CommonName: "laptop", Port: 13000, FullMesh: true}
}

func (stubSource) Neighbors() []control.Neighbor {
	return []control.Neighbor{{Peer: "example/gateway@0", Alive: true, Cost: 116, Routes: 15}}
}

func (stubSource) Routes() []control.Route {
	return []control.Route{{Destination: netip.MustParsePrefix("198.18.104.117/32"), Originated: true}}
}

func (stubSource) Sessions() []control.Session {
	return []control.Session{{Path: "example/gateway/0@0", Peer: "example/gateway", Active: true}}
}

func (stubSource) Peers() []control.Peer {
	return []control.Peer{{Path: "example/gateway/@0", Organization: "example", CommonName: "gateway", Connected: true}}
}

// serveStub starts a control socket for one test and returns its path.
func serveStub(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "control.sock")
	listener, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go control.Serve(listener, stubSource{})
	return path
}

// A first argument that is not a flag asks for the client, and anything
// starting with a dash is the daemon's command line, so an existing
// deployment's `ranet-lite -config ...` is untouched.
func TestSubcommandIsAFirstArgumentWithoutADash(t *testing.T) {
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"a command":          {args: []string{"status"}, want: "status"},
		"a command and flag": {args: []string{"routes", "-json"}, want: "routes"},
		"the daemon":         {args: []string{"-config", "/etc/x.yaml"}},
		"nothing at all":     {args: nil},
	} {
		t.Run(name, func(t *testing.T) {
			got, rest, ok := subcommand(test.args)
			if ok != (test.want != "") {
				t.Fatalf("subcommand(%q) reported %v", test.args, ok)
			}
			if got != test.want {
				t.Errorf("subcommand(%q) = %q, want %q", test.args, got, test.want)
			}
			if ok && len(rest) != len(test.args)-1 {
				t.Errorf("the remaining arguments are %q", rest)
			}
		})
	}
}

// Every command reaches a live socket and prints the subsystem it names.
func TestCommandsReadTheirOwnSubsystem(t *testing.T) {
	socket := serveStub(t)
	for name, want := range map[string]string{
		"status":    "example/laptop",
		"neighbors": "example/gateway@0",
		"routes":    "198.18.104.117/32",
		"sessions":  "example/gateway/0@0",
		"peers":     "gateway",
	} {
		t.Run(name, func(t *testing.T) {
			var out, usage strings.Builder
			if code := runCommand(name, []string{"-control", socket}, &out, &usage); code != 0 {
				t.Fatalf("%s exited %d: %s", name, code, usage.String())
			}
			if !strings.Contains(out.String(), want) {
				t.Errorf("%s printed %q, want it to carry %q", name, out.String(), want)
			}
		})
	}
}

// -json is the wire form, so a script parses the same field names the daemon
// serves rather than the table's column headings.
func TestJSONPrintsTheWireForm(t *testing.T) {
	socket := serveStub(t)
	var out, usage strings.Builder
	if code := runCommand("status", []string{"-control", socket, "-json"}, &out, &usage); code != 0 {
		t.Fatalf("status -json exited %d: %s", code, usage.String())
	}
	for _, want := range []string{`"common_name": "laptop"`, `"full_mesh": true`} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status -json printed %q, want it to carry %q", out.String(), want)
		}
	}
}

// A mistyped command, a stray argument and a daemon that is not running each
// exit nonzero and say which of the three happened.
func TestCommandsRefuseWhatTheyCannotActOn(t *testing.T) {
	socket := serveStub(t)
	for name, test := range map[string]struct {
		command string
		args    []string
		want    string
	}{
		"an unknown command": {command: "neighbours", want: "unknown command"},
		"a stray argument":   {command: "status", args: []string{"-control", socket, "extra"}, want: "takes no arguments"},
		"no daemon":          {command: "status", args: []string{"-control", filepath.Join(t.TempDir(), "gone.sock")}, want: "daemon"},
	} {
		t.Run(name, func(t *testing.T) {
			var out, usage strings.Builder
			if code := runCommand(test.command, test.args, &out, &usage); code == 0 {
				t.Fatalf("%q was accepted, printing %q", test.command, out.String())
			}
			if !strings.Contains(usage.String(), test.want) {
				t.Errorf("the refusal reads %q, want it to carry %q", usage.String(), test.want)
			}
		})
	}
}

// An unknown command lists the ones that exist and says where the daemon is,
// which is the question somebody typing a wrong one is asking.
func TestUnknownCommandNamesTheOnesThatExist(t *testing.T) {
	var out, usage strings.Builder
	runCommand("neighbours", nil, &out, &usage)
	for _, want := range []string{"neighbors", "routes", "sessions", "peers", "status", "runs the daemon"} {
		if !strings.Contains(usage.String(), want) {
			t.Errorf("the usage reads %q, want it to carry %q", usage.String(), want)
		}
	}
}

// -h on a subcommand is a request the flag package answers, and reporting it
// as a failure prints "flag: help requested" under the usage and exits 1.
func TestSubcommandHelpExitsClean(t *testing.T) {
	var usage strings.Builder
	if code := runCommand("status", []string{"-h"}, io.Discard, &usage); code != 0 {
		t.Errorf("asking for help exited %d", code)
	}
	if !strings.Contains(usage.String(), "-control") {
		t.Errorf("the usage does not name the flags: %q", usage.String())
	}
}
