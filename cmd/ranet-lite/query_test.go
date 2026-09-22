package main

import (
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"

	"github.com/NickCao/ranet-lite/control"
)

// meshStub answers with a route table and an originate set rich enough for the
// four queries to have something to separate, which the flat stubSource does
// not: one prefix covering another, a default from an exit, and a prefix this
// node announces itself.
type meshStub struct{ stubSource }

func (meshStub) Status() control.Status {
	return control.Status{
		Organization: "example", CommonName: "laptop", Version: "1.2.3",
		Originate: []control.Originated{
			{Prefix: netip.MustParsePrefix("198.18.104.117/32")},
			{Prefix: netip.MustParsePrefix("2001:db8:1::5/128")},
			{Prefix: netip.MustParsePrefix("2001:db8:9::/48")},
		},
	}
}

func (meshStub) Routes() []control.Route {
	return []control.Route{
		{Destination: netip.MustParsePrefix("2001:db8::/32"), Via: "example/core@0", Metric: 212, Candidates: 4},
		{Destination: netip.MustParsePrefix("2001:db8:1::/48"), Via: "example/gateway@0", Metric: 116, Candidates: 3},
		{Destination: netip.MustParsePrefix("::/0"), From: netip.MustParsePrefix("2001:db8::/32"), Via: "example/exit@0", Metric: 300, Candidates: 2},
		{Destination: netip.MustParsePrefix("198.18.104.117/32"), Originated: true},
	}
}

func (meshStub) Metrics(w io.Writer) { io.WriteString(w, "ranet_lite_sessions 2\n") }

// serveMesh starts a socket behind a node with something to query.
func serveMesh(t *testing.T) string {
	t.Helper()
	path := socketPath(t)
	listener, err := control.Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { listener.Close() })
	go control.Serve(listener, meshStub{})
	return path
}

// Each query answers from the read paths, so none of them needs anything the
// daemon does not already serve.
func TestQueriesAnswerFromTheReads(t *testing.T) {
	socket := serveMesh(t)
	for name, test := range map[string]struct {
		args []string
		want []string
	}{
		"whois in a covering prefix": {
			args: []string{"whois", "2001:db8:1::9"},
			want: []string{"2001:db8:1::9 is in 2001:db8:1::/48", "example/gateway@0", "2001:db8::/32"},
		},
		"whois in this node's own": {
			args: []string{"whois", "198.18.104.117"},
			want: []string{"this node originates"},
		},
		"ip": {
			args: []string{"ip"},
			want: []string{"198.18.104.117", "2001:db8:1::5"},
		},
		"exit-node list": {
			args: []string{"exit-node", "list"},
			want: []string{"example/exit@0", "selected", "2001:db8::/32"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			out, err := execute(t, append(test.args, "--control", socket)...)
			if err != nil {
				t.Fatalf("%v failed: %v", test.args, err)
			}
			for _, want := range test.want {
				if !strings.Contains(out, want) {
					t.Errorf("%v printed %q, want it to carry %q", test.args, out, want)
				}
			}
		})
	}
}

// ip prints the addresses this node answers at and nothing else, since the
// output goes into a shell variable rather than being read.
func TestIPPrintsOnlyTheHostPrefixes(t *testing.T) {
	socket := serveMesh(t)
	out, err := execute(t, "ip", "--control", socket)
	if err != nil {
		t.Fatalf("ip failed: %v", err)
	}
	if out != "198.18.104.117\n2001:db8:1::5\n" {
		t.Errorf("ip printed %q", out)
	}
}

// bugreport carries every subsystem in one object, with the binary's own
// version beside the daemon's so a report says which halves were talking.
func TestBugreportCarriesEverySubsystem(t *testing.T) {
	socket := serveMesh(t)
	out, err := execute(t, "bugreport", "--control", socket)
	if err != nil {
		t.Fatalf("bugreport failed: %v", err)
	}
	var report bugreport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("bugreport is not json: %v in %q", err, out)
	}
	switch {
	case report.Status == nil || report.Status.CommonName != "laptop":
		t.Errorf("the report carries no status: %+v", report.Status)
	case len(report.Neighbors) == 0:
		t.Error("the report carries no neighbors")
	case len(report.Routes) == 0:
		t.Error("the report carries no routes")
	case len(report.Sessions) == 0:
		t.Error("the report carries no sessions")
	case len(report.Peers) == 0:
		t.Error("the report carries no peers")
	case !strings.Contains(report.Metrics, "ranet_lite_sessions"):
		t.Errorf("the report carries no scrape: %q", report.Metrics)
	case report.Socket != socket:
		t.Errorf("the report names %q as the socket it read", report.Socket)
	case len(report.Refused) != 0:
		t.Errorf("a node that answered everything refused %v", report.Refused)
	}
}

// A node that answers nothing still produces a report, naming each read that
// did not answer. One failing read replacing the report would send whoever is
// collecting it back to gather the rest by hand.
func TestBugreportSurvivesADaemonThatIsNotThere(t *testing.T) {
	out, err := execute(t, "bugreport", "--control", socketPath(t))
	if err != nil {
		t.Fatalf("bugreport failed against a node that is not running: %v", err)
	}
	var report bugreport
	if err := json.Unmarshal([]byte(out), &report); err != nil {
		t.Fatalf("bugreport is not json: %v in %q", err, out)
	}
	if len(report.Refused) != 6 {
		t.Errorf("%d reads were named as refused, want all six: %v", len(report.Refused), report.Refused)
	}
	if report.Status != nil {
		t.Errorf("a status that never arrived is reported as %+v", report.Status)
	}
	if report.Binary == "" {
		t.Error("the report does not say which binary took it")
	}
}

// --json on a query is the wire form, so a script reads the route entries
// rather than the sentence.
func TestQueryJSONPrintsTheWireForm(t *testing.T) {
	socket := serveMesh(t)
	out, err := execute(t, "whois", "2001:db8:1::9", "--control", socket, "--json")
	if err != nil {
		t.Fatalf("whois --json failed: %v", err)
	}
	if !strings.Contains(out, `"destination": "2001:db8:1::/48"`) {
		t.Errorf("whois --json printed %q", out)
	}
}

// An argument that is not an address is refused here, naming what was typed,
// rather than reaching the daemon and matching nothing.
func TestWhoisRefusesWhatIsNotAnAddress(t *testing.T) {
	socket := serveMesh(t)
	if _, err := execute(t, "whois", "2001:db8:1::/48", "--control", socket); err == nil {
		t.Error("whois took a prefix")
	} else if !strings.Contains(err.Error(), "2001:db8:1::/48") {
		t.Errorf("the refusal reads %q, want it to name what was typed", err)
	}
	if _, err := execute(t, "whois", "--control", socket); err == nil {
		t.Error("whois took no address at all")
	}
}
