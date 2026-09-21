package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"slices"
	"strings"

	"github.com/NickCao/ranet-lite/internal/control"
)

// This file is the client half of the binary: `ranet-lite status` and its
// siblings read the daemon's control socket and print it. They are
// subcommands of the same binary rather than a second one because a fleet
// deploys one file, and because the wire types and the renderer are then
// shared with the daemon by the compiler rather than by hand.
//
// Everything here is read-only. There is no subcommand that changes the
// node's configuration, because the configuration's entry points are its file
// and SIGHUP, and a socket that could write would need an authorization story
// to replace the one the file's permissions already are.

// command is one subcommand: what it reads and how it prints it.
type command struct {
	summary string
	run     func(*control.Client, io.Writer, bool) error
}

var commands = map[string]command{
	"status": {
		summary: "this node: identity, role, counts and the reconciler's last pass",
		run: func(c *control.Client, w io.Writer, asJSON bool) error {
			status, err := c.Status()
			if err != nil {
				return err
			}
			return print(w, asJSON, status, func() { control.RenderStatus(w, status) })
		},
	},
	"neighbors": {
		summary: "babel neighbors, their link costs and what each one is offering",
		run: func(c *control.Client, w io.Writer, asJSON bool) error {
			neighbors, err := c.Neighbors()
			if err != nil {
				return err
			}
			return print(w, asJSON, neighbors, func() { control.RenderNeighbors(w, neighbors) })
		},
	},
	"routes": {
		summary: "the mesh route table, selected and held alike",
		run: func(c *control.Client, w io.Writer, asJSON bool) error {
			routes, err := c.Routes()
			if err != nil {
				return err
			}
			return print(w, asJSON, routes, func() { control.RenderRoutes(w, routes) })
		},
	},
	"sessions": {
		summary: "live IKE SAs, their SPIs and how long since each peer last answered",
		run: func(c *control.Client, w io.Writer, asJSON bool) error {
			sessions, err := c.Sessions()
			if err != nil {
				return err
			}
			return print(w, asJSON, sessions, func() { control.RenderSessions(w, sessions) })
		},
	},
	"peers": {
		summary: "who this node dials, from the config file or from the registry, and whether it got there",
		run: func(c *control.Client, w io.Writer, asJSON bool) error {
			peers, err := c.Peers()
			if err != nil {
				return err
			}
			return print(w, asJSON, peers, func() { control.RenderPeers(w, peers) })
		},
	},
}

// print writes one answer, as indented JSON or through its renderer. The JSON
// is re-encoded from the decoded value rather than passed through, so a client
// and a daemon that disagree about a field show that disagreement here rather
// than hiding it behind the daemon's own bytes.
func print(w io.Writer, asJSON bool, value any, render func()) error {
	if !asJSON {
		render()
		return nil
	}
	body, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintf(w, "%s\n", body)
	return err
}

// commandNames is the subcommands in a fixed order, for a usage message that
// does not shuffle between runs.
func commandNames() []string {
	names := make([]string, 0, len(commands))
	for name := range commands {
		names = append(names, name)
	}
	slices.Sort(names)
	return names
}

// subcommand decides whether a command line asks for the client rather than
// the daemon. A first argument that is not a flag is the only signal, so
// `ranet-lite -config ...` keeps starting the daemon exactly as before and a
// deployment needs no change.
func subcommand(args []string) (string, []string, bool) {
	if len(args) == 0 || strings.HasPrefix(args[0], "-") {
		return "", nil, false
	}
	return args[0], args[1:], true
}

// runCommand parses one subcommand's flags and runs it. It returns the process
// status, so that a refusal and a failed read both leave through one place.
func runCommand(name string, args []string, out, usage io.Writer) int {
	cmd, known := commands[name]
	if !known {
		fmt.Fprintf(usage, "ranet-lite: unknown command %q\n", name)
		writeCommandUsage(usage)
		return 1
	}
	fs := flag.NewFlagSet("ranet-lite "+name, flag.ContinueOnError)
	fs.SetOutput(usage)
	socket := fs.String("control", control.DefaultSocket, "path to the daemon's control socket")
	asJSON := fs.Bool("json", false, "print the wire form instead of a table")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 1
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(usage, "ranet-lite %s takes no arguments, got %q\n", name, fs.Arg(0))
		return 1
	}
	if err := cmd.run(control.Dial(*socket), out, *asJSON); err != nil {
		fmt.Fprintf(usage, "%v\n", err)
		return 1
	}
	return 0
}

// writeCommandUsage names the subcommands and says that the bare binary is the
// daemon, which is the question somebody typing a wrong one is asking.
func writeCommandUsage(w io.Writer) {
	fmt.Fprint(w, "usage: ranet-lite <command> [-control <socket>] [-json]\n\ncommands:\n")
	for _, name := range commandNames() {
		fmt.Fprintf(w, "  %-10s %s\n", name, commands[name].summary)
	}
	fmt.Fprint(w, "\nranet-lite with no command, or with a flag first, runs the daemon; see -h.\n")
}
