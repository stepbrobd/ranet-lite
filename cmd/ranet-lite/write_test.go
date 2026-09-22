package main

import (
	"fmt"
	"strings"
	"sync"
	"testing"

	"github.com/spf13/cobra"

	"github.com/NickCao/ranet-lite/control"
)

// writingStub is a stubSource that also takes the verbs, recording the call so
// a test can tell a command that reached the daemon from one that printed
// something plausible without asking it anything.
type writingStub struct {
	stubSource
	mu   sync.Mutex
	last string
}

func (s *writingStub) SetSubsystem(name control.Subsystem, on bool) (control.Result, error) {
	state := "stopped"
	if on {
		state = "running"
	}
	return s.record(fmt.Sprintf("set %s %s", name, state))
}

func (s *writingStub) Redial(peer string) (control.Result, error) {
	return s.record("redial " + peer)
}

func (s *writingStub) Rekey(peer string, all bool) (control.Result, error) {
	if all {
		return s.record("rekey --all")
	}
	return s.record("rekey " + peer)
}

func (s *writingStub) Reload() (control.Result, error) { return s.record("reload") }

func (s *writingStub) record(call string) (control.Result, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.last = call
	return control.Result{Acted: []string{call}, Detail: "the daemon took " + call}, nil
}

func (s *writingStub) asked() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last
}

// serveWritingStub starts a control socket that takes the verbs and returns
// its path with the stub behind it.
func serveWritingStub(t *testing.T) (string, *writingStub) {
	t.Helper()
	path := socketPath(t)
	listener, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	sink := &writingStub{}
	go control.Serve(listener, sink)
	return path, sink
}

// Every verb reaches the daemon with the argument that was typed, and prints
// the sentence the daemon answered rather than one of its own.
func TestVerbsReachTheDaemonAsTyped(t *testing.T) {
	socket, sink := serveWritingStub(t)
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"disable":   {args: []string{"disable", "steering"}, want: "set steering stopped"},
		"enable":    {args: []string{"enable", "reconciler"}, want: "set reconciler running"},
		"redial":    {args: []string{"redial", "example/gateway"}, want: "redial example/gateway"},
		"rekey one": {args: []string{"rekey", "example/gateway"}, want: "rekey example/gateway"},
		"rekey all": {args: []string{"rekey", "--all"}, want: "rekey --all"},
		"reload":    {args: []string{"reload"}, want: "reload"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, append(test.args, "--control", socket)...)
			if err != nil {
				t.Fatalf("%v failed: %v", test.args, err)
			}
			if got := sink.asked(); got != test.want {
				t.Errorf("the daemon was asked %q, want %q", got, test.want)
			}
			if !strings.Contains(out, test.want) {
				t.Errorf("the command printed %q, want the daemon's own answer", out)
			}
		})
	}
}

// --json on a verb is the answer as a script parses it, so a fleet tool reads
// the field names the daemon serves rather than the sentence.
func TestVerbJSONPrintsTheWireForm(t *testing.T) {
	socket, _ := serveWritingStub(t)
	out, err := execute(t, "reload", "--control", socket, "--json")
	if err != nil {
		t.Fatalf("reload --json failed: %v", err)
	}
	if !strings.Contains(out, `"detail"`) || !strings.Contains(out, `"acted"`) {
		t.Errorf("reload --json printed %q", out)
	}
}

// A verb given the wrong arguments is refused here rather than at the daemon,
// and a daemon that refuses says why in its own words.
func TestVerbsRefuseWhatTheyCannotActOn(t *testing.T) {
	socket, _ := serveWritingStub(t)
	for name, test := range map[string]struct {
		args []string
		want string
	}{
		"disable with no subsystem": {args: []string{"disable"}, want: "arg"},
		"disable with two":          {args: []string{"disable", "steering", "responder"}, want: "arg"},
		"rekey with neither":        {args: []string{"rekey"}, want: "arg"},
		"rekey with both":           {args: []string{"rekey", "example/gateway", "--all"}, want: "takes no arguments"},
		"reload with an argument":   {args: []string{"reload", "now"}, want: "takes no arguments"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, append(test.args, "--control", socket)...)
			if err == nil {
				t.Fatalf("%v was accepted, printing %q", test.args, out)
			}
			if !strings.Contains(err.Error(), test.want) {
				t.Errorf("the refusal reads %q, want it to carry %q", err, test.want)
			}
		})
	}
}

// A verb against a daemon that is not running says so, rather than reporting a
// change nothing made.
func TestVerbsSayWhenNoDaemonAnswers(t *testing.T) {
	gone := socketPath(t)
	for _, args := range [][]string{{"disable", "steering"}, {"redial", "gateway"}, {"rekey", "--all"}, {"reload"}} {
		if _, err := execute(t, append(args, "--control", gone)...); err == nil {
			t.Errorf("%v reported success against a socket nothing is serving", args)
		} else if !strings.Contains(err.Error(), "daemon") {
			t.Errorf("the failure reads %q, want it to name the daemon", err)
		}
	}
}

// A subsystem is completed from the closed set, which a node that is not
// running still answers for, and a peer is completed from the daemon, which
// knows what this node dials and answers.
func TestVerbArgumentsAreCompleted(t *testing.T) {
	socket, _ := serveWritingStub(t)
	for name, test := range map[string]struct {
		command string
		want    string
	}{
		"a subsystem": {command: "disable", want: "steering"},
		"a peer":      {command: "redial", want: "example/gateway"},
		"a session":   {command: "rekey", want: "example/gateway"},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, cobra.ShellCompRequestCmd, test.command, "--control", socket, "")
			if err != nil {
				t.Fatalf("completing %s failed: %v", test.command, err)
			}
			if !strings.Contains(out, test.want) {
				t.Errorf("%s completed to %q, want it to offer %q", test.command, out, test.want)
			}
		})
	}
}

// The usage lists the verbs beside the reads, because the bare binary's
// listing is the whole of the built-in documentation.
func TestBareInvocationListsTheVerbs(t *testing.T) {
	out, err := execute(t)
	if err != nil {
		t.Fatalf("the bare binary failed: %v", err)
	}
	for _, want := range []string{"disable", "enable", "redial", "rekey", "reload"} {
		if !strings.Contains(out, want) {
			t.Errorf("the usage reads %q, want it to name %q", out, want)
		}
	}
}
