package main

import (
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/NickCao/ranet-lite/internal/control"
)

// stubSource stands in for a running node, so the subcommands are exercised
// over a real socket without one.
type stubSource struct{}

func (stubSource) Status() control.Status {
	return control.Status{Organization: "example", CommonName: "laptop", Port: 13000, FullMesh: true, Version: "1.2.3"}
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
	path := socketPath(t)
	listener, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go control.Serve(listener, stubSource{})
	return path
}

// socketPath names a socket short enough to bind. See the same helper in
// internal/control/server_test.go for what t.TempDir() costs on darwin.
func socketPath(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "rl")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	path := filepath.Join(dir, "control.sock")
	if len(path) > control.MaxSocketPath {
		t.Fatalf("this TMPDIR leaves no room for a socket: %s is %d bytes", path, len(path))
	}
	return path
}

// execute drives the real command tree with its output captured, which is the
// same tree main runs. The arguments are copied into a non-nil slice because
// cobra reads the process command line when it is handed nil, which under a
// test binary is that binary's own flags.
func execute(t *testing.T, args ...string) (string, error) {
	t.Helper()
	var out strings.Builder
	root := newRoot()
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs(append([]string{}, args...))
	err := root.Execute()
	return out.String(), err
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
			out, err := execute(t, name, "--control", socket)
			if err != nil {
				t.Fatalf("%s failed: %v", name, err)
			}
			if !strings.Contains(out, want) {
				t.Errorf("%s printed %q, want it to carry %q", name, out, want)
			}
		})
	}
}

// --json is the wire form, so a script parses the same field names the daemon
// serves rather than the table's column headings.
func TestJSONPrintsTheWireForm(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, "status", "--control", socket, "--json")
	if err != nil {
		t.Fatalf("status --json failed: %v", err)
	}
	for _, want := range []string{`"common_name": "laptop"`, `"full_mesh": true`} {
		if !strings.Contains(out, want) {
			t.Errorf("status --json printed %q, want it to carry %q", out, want)
		}
	}
}

// version answers about the binary by default and about the node on the other
// end of the socket with --daemon. The two differ for exactly as long as an
// upgraded file waits for a restart.
func TestVersionAnswersForTheBinaryOrTheDaemon(t *testing.T) {
	socket := serveStub(t)
	out, err := execute(t, "version", "--daemon", "--control", socket)
	if err != nil {
		t.Fatalf("version --daemon failed: %v", err)
	}
	if strings.TrimSpace(out) != "1.2.3" {
		t.Errorf("version --daemon printed %q, want the running node's", out)
	}
	out, err = execute(t, "version")
	if err != nil {
		t.Fatalf("version failed: %v", err)
	}
	if strings.TrimSpace(out) == "1.2.3" {
		t.Error("version reported the stub daemon's rather than this binary's")
	}
}

// A mistyped command, a stray argument and a daemon that is not running each
// fail and say which of the three happened.
func TestCommandsRefuseWhatTheyCannotActOn(t *testing.T) {
	socket := serveStub(t)
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"an unknown command": {args: []string{"neighbours"}, want: "unknown command"},
		"a stray argument":   {args: []string{"status", "--control", socket, "extra"}, want: "takes no arguments"},
		"no daemon":          {args: []string{"status", "--control", filepath.Join(filepath.Dir(socketPath(t)), "gone.sock")}, want: "daemon"},
		// A reader given a path the kernel will not take is told the same
		// thing the daemon is told, rather than "connect: invalid argument".
		"a path over the limit": {args: []string{"status", "--control", filepath.Join(t.TempDir(), strings.Repeat("d", control.MaxSocketPath), "control.sock")}, want: "unix socket holds"},
		"an unknown shell":      {args: []string{"completion", "tcsh"}, want: "tcsh"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, test.args...)
			if err == nil {
				t.Fatalf("%q was accepted, printing %q", test.args, out)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("the refusal reads %q, want it to carry %q", err, test.want)
			}
		})
	}
}

// A mistyped command names the one that was meant, which is the question
// somebody typing a wrong one is asking.
func TestUnknownCommandSuggestsTheOneThatExists(t *testing.T) {
	_, err := execute(t, "neighbours")
	if err == nil {
		t.Fatal("a mistyped command was accepted")
	}
	if !strings.Contains(err.Error(), "neighbors") {
		t.Errorf("the refusal reads %q, want it to suggest neighbors", err)
	}
}

// The bare binary lists what it can do, the daemon included, rather than
// starting a node nobody asked for.
func TestBareInvocationListsTheCommands(t *testing.T) {
	out, err := execute(t)
	if err != nil {
		t.Fatalf("the bare binary failed: %v", err)
	}
	for _, want := range []string{"daemon", "neighbors", "routes", "sessions", "peers", "status", "completion", "version"} {
		if !strings.Contains(out, want) {
			t.Errorf("the usage reads %q, want it to name %q", out, want)
		}
	}
}

// The completion scripts are generated from the command tree, so a command
// added without one is completed anyway. Each shell is asked for its own.
func TestCompletionCoversEveryShell(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			out, err := execute(t, "completion", shell)
			if err != nil {
				t.Fatalf("completion %s failed: %v", shell, err)
			}
			if !strings.Contains(out, "ranet-lite") {
				t.Errorf("the %s script does not name the binary: %q", shell, out)
			}
		})
	}
}

// --help is a request cobra answers by writing the usage, and reporting it as
// a failure exits nonzero on a question that was answered.
func TestSubcommandHelpExitsClean(t *testing.T) {
	out, err := execute(t, "status", "--help")
	if err != nil {
		t.Errorf("asking for help failed: %v", err)
	}
	if !strings.Contains(out, "--control") {
		t.Errorf("the usage does not name the flags: %q", out)
	}
}

// Every command carries a one-line summary, because the bare binary's listing
// is the whole of the built-in documentation.
func TestEveryCommandIsDescribed(t *testing.T) {
	var walk func(*cobra.Command)
	walk = func(cmd *cobra.Command) {
		if cmd.Name() != "help" && cmd.Short == "" {
			t.Errorf("%s has no summary", cmd.CommandPath())
		}
		for _, child := range cmd.Commands() {
			walk(child)
		}
	}
	walk(newRoot())
}
