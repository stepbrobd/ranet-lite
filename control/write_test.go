package control

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// writingSource is a fakeSource that also takes the verbs, recording what it
// was asked so a test can tell a handler that routed a verb from one that
// answered a different one.
type writingSource struct {
	fakeSource
	subsystem Subsystem
	on        bool
	peer      string
	all       bool
	verb      string
	refuse    error
}

func (s *writingSource) SetSubsystem(name Subsystem, on bool) (Result, error) {
	s.verb, s.subsystem, s.on = "set", name, on
	return s.answer(string(name))
}

func (s *writingSource) Redial(peer string) (Result, error) {
	s.verb, s.peer = "redial", peer
	return s.answer(peer)
}

func (s *writingSource) Rekey(peer string, all bool) (Result, error) {
	s.verb, s.peer, s.all = "rekey", peer, all
	return s.answer(peer)
}

func (s *writingSource) Reload() (Result, error) {
	s.verb = "reload"
	return s.answer("/etc/ranet-lite/config.toml")
}

func (s *writingSource) answer(acted string) (Result, error) {
	if s.refuse != nil {
		return Result{}, s.refuse
	}
	return Result{Acted: []string{acted}, Detail: "took " + s.verb}, nil
}

// post sends one write and hands back the answer, so each test below reads as
// the verb it checks rather than as four lines of transport.
func post(t *testing.T, url, body string) *http.Response {
	t.Helper()
	response, err := http.Post(url, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { response.Body.Close() })
	return response
}

// Every verb reaches its own method with its own arguments, so a handler that
// wires two paths to one call is caught rather than passing.
func TestHandlerRoutesEveryVerb(t *testing.T) {
	for name, test := range map[string]struct {
		path  string
		body  string
		check func(*testing.T, *writingSource)
	}{
		"disable": {path: PathDisable, body: `{"subsystem":"steering"}`, check: func(t *testing.T, s *writingSource) {
			if s.verb != "set" || s.subsystem != SubsystemSteering || s.on {
				t.Errorf("disable reached %+v", s)
			}
		}},
		"enable": {path: PathEnable, body: `{"subsystem":"responder"}`, check: func(t *testing.T, s *writingSource) {
			if s.verb != "set" || s.subsystem != SubsystemResponder || !s.on {
				t.Errorf("enable reached %+v", s)
			}
		}},
		"redial": {path: PathRedial, body: `{"peer":"example/gateway"}`, check: func(t *testing.T, s *writingSource) {
			if s.verb != "redial" || s.peer != "example/gateway" {
				t.Errorf("redial reached %+v", s)
			}
		}},
		"rekey one": {path: PathRekey, body: `{"peer":"example/gateway"}`, check: func(t *testing.T, s *writingSource) {
			if s.verb != "rekey" || s.peer != "example/gateway" || s.all {
				t.Errorf("rekey reached %+v", s)
			}
		}},
		"rekey all": {path: PathRekey, body: `{"all":true}`, check: func(t *testing.T, s *writingSource) {
			if s.verb != "rekey" || !s.all {
				t.Errorf("rekey --all reached %+v", s)
			}
		}},
		// Empty rather than "{}": reload reads no field, so it is asked with
		// no body at all and the handler has to take that as the zero request.
		"reload": {path: PathReload, body: "", check: func(t *testing.T, s *writingSource) {
			if s.verb != "reload" {
				t.Errorf("reload reached %+v", s)
			}
		}},
	} {
		t.Run(name, func(t *testing.T) {
			sink := &writingSource{}
			server := httptest.NewServer(Handler(sink))
			defer server.Close()
			response := post(t, server.URL+test.path, test.body)
			if response.StatusCode != http.StatusOK {
				t.Fatalf("%s answered %s", test.path, response.Status)
			}
			test.check(t, sink)
			var result Result
			if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
				t.Fatal(err)
			}
			if result.Detail == "" {
				t.Errorf("%s answered without a sentence: %+v", test.path, result)
			}
		})
	}
}

// The method is the line between the two halves. A read never writes and a
// write never answers a caller that arrived by GET, so neither half is reached
// by aiming the other one's method at it.
func TestMethodSeparatesReadsFromWrites(t *testing.T) {
	server := httptest.NewServer(Handler(&writingSource{}))
	defer server.Close()

	response := post(t, server.URL+PathStatus, "{}")
	if response.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to a read answered %s, want 405", response.Status)
	}
	if allow := response.Header.Get("Allow"); !strings.Contains(allow, "GET") {
		t.Errorf("the refusal advertises %q, want it to name GET", allow)
	}

	got, err := http.Get(server.URL + PathDisable)
	if err != nil {
		t.Fatal(err)
	}
	defer got.Body.Close()
	if got.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a GET to a write answered %s, want 405", got.Status)
	}
	if allow := got.Header.Get("Allow"); !strings.Contains(allow, "POST") {
		t.Errorf("the refusal advertises %q, want it to name POST", allow)
	}
}

// A Source that does not write serves the reads and refuses the verbs by name.
// A 404 would say the path does not exist, which is a different problem from a
// node that takes no writes.
func TestReadOnlySourceRefusesEveryVerb(t *testing.T) {
	server := httptest.NewServer(Handler(fakeSource{}))
	defer server.Close()
	for _, path := range []string{PathDisable, PathEnable, PathRedial, PathRekey, PathReload} {
		response := post(t, server.URL+path, "{}")
		if response.StatusCode != http.StatusNotImplemented {
			t.Errorf("%s answered %s on a read-only source, want 501", path, response.Status)
		}
		body, _ := io.ReadAll(response.Body)
		if !strings.Contains(string(body), "reads only") {
			t.Errorf("%s refused with %q, want it to say the node takes no writes", path, body)
		}
	}
}

// A verb that found nothing to act on is an error the caller reads rather than
// a quiet success, and the handler carries the daemon's own sentence.
func TestWriteRefusalCarriesItsSentence(t *testing.T) {
	sink := &writingSource{refuse: errors.New("control: this node steers nothing")}
	server := httptest.NewServer(Handler(sink))
	defer server.Close()
	response := post(t, server.URL+PathDisable, `{"subsystem":"steering"}`)
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("a refused verb answered %s, want 400", response.Status)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "steers nothing") {
		t.Errorf("the refusal reads %q, want the daemon's own sentence", body)
	}
}

// Every verb round trips over a real socket, which is the check that the client
// and the handler agree about paths and field names as well as about types.
func TestClientRoundTripsEveryVerb(t *testing.T) {
	path := socketPath(t)
	listener, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	sink := &writingSource{}
	go Serve(listener, sink)

	client := Dial(path)
	if _, err := client.Disable(SubsystemReconciler); err != nil {
		t.Fatal(err)
	}
	if sink.subsystem != SubsystemReconciler || sink.on {
		t.Errorf("disable arrived as %+v", sink)
	}
	if _, err := client.Enable(SubsystemReconciler); err != nil {
		t.Fatal(err)
	}
	if !sink.on {
		t.Errorf("enable arrived as %+v", sink)
	}
	if _, err := client.Redial("example/gateway"); err != nil {
		t.Fatal(err)
	}
	if sink.verb != "redial" || sink.peer != "example/gateway" {
		t.Errorf("redial arrived as %+v", sink)
	}
	if _, err := client.Rekey("", true); err != nil {
		t.Fatal(err)
	}
	if sink.verb != "rekey" || !sink.all {
		t.Errorf("rekey --all arrived as %+v", sink)
	}
	result, err := client.Reload()
	if err != nil {
		t.Fatal(err)
	}
	if sink.verb != "reload" || result.Detail == "" {
		t.Errorf("reload arrived as %+v answering %+v", sink, result)
	}
}

// The scrape is a read, so it answers a GET and refuses a POST like the rest
// of them, and it is served as the exposition format rather than as JSON.
func TestMetricsAreServedAsTheExpositionFormat(t *testing.T) {
	server := httptest.NewServer(Handler(fakeSource{}))
	defer server.Close()
	response, err := http.Get(server.URL + PathMetrics)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if got := response.Header.Get("Content-Type"); !strings.HasPrefix(got, "text/plain") {
		t.Errorf("the scrape is served as %q", got)
	}
	body, _ := io.ReadAll(response.Body)
	if !strings.Contains(string(body), "ranet_lite_sessions 1") {
		t.Errorf("the scrape reads %q", body)
	}
	if refused := post(t, server.URL+PathMetrics, "{}"); refused.StatusCode != http.StatusMethodNotAllowed {
		t.Errorf("a POST to the scrape answered %s, want 405", refused.Status)
	}
}

// A subsystem somebody stopped is reported, because the node is then running
// less than its file says and nothing else on the status says so.
func TestStatusNamesStoppedSubsystems(t *testing.T) {
	var out strings.Builder
	RenderStatus(&out, Status{Organization: "example", CommonName: "laptop"})
	if strings.Contains(out.String(), "disabled") {
		t.Errorf("a node with everything running reports %q", out.String())
	}
	out.Reset()
	RenderStatus(&out, Status{Organization: "example", CommonName: "laptop",
		Disabled: []Subsystem{SubsystemReconciler, SubsystemSteering}})
	for _, want := range []string{"disabled", "reconciler, steering", "restart"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("status printed %q, want it to carry %q", out.String(), want)
		}
	}
}
