package main

import (
	"encoding/json"
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/NickCao/ranet-lite/control"
	"github.com/NickCao/ranet-lite/internal/notices"
	"github.com/NickCao/ranet-lite/internal/version"
)

// This file is the command tree. `ranet-lite daemon` is the node itself and
// every other command reads a running one's control socket and prints it. They
// are subcommands of one binary rather than two programs because a fleet
// deploys one file, and because the wire types and the renderer are then
// shared with the daemon by the compiler rather than by hand.
//
// Every command but daemon is read-only. There is no subcommand that changes
// the node's configuration, because the configuration's entry points are its
// file and SIGHUP, and a socket that could write would need an authorization
// story to replace the one the file's permissions already are.

// reader holds the two flags every read takes. One value is shared by all of
// them because cobra parses the flags of the one command that runs.
type reader struct {
	socket string
	asJSON bool
}

// newRoot builds the command tree. It takes no process state, so a test drives
// the same tree main does with its own arguments and its own output.
func newRoot() *cobra.Command {
	r := &reader{}
	root := &cobra.Command{
		Use:     "ranet-lite",
		Short:   "A ranet mesh node, and the commands that read one",
		Version: version.String(),
		// main prints the one error and the usage is on --help, so neither is
		// written twice.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.AddCommand(
		daemonCommand(),
		r.command("status", "this node: identity, role, counts and the reconciler's last pass",
			func(c *control.Client, w io.Writer, asJSON bool) error {
				status, err := c.Status()
				if err != nil {
					return err
				}
				return emit(w, asJSON, status, func() { control.RenderStatus(w, status) })
			}),
		r.command("neighbors", "babel neighbors, their link costs and what each one is offering",
			func(c *control.Client, w io.Writer, asJSON bool) error {
				neighbors, err := c.Neighbors()
				if err != nil {
					return err
				}
				return emit(w, asJSON, neighbors, func() { control.RenderNeighbors(w, neighbors) })
			}),
		r.command("routes", "the mesh route table, selected and held alike",
			func(c *control.Client, w io.Writer, asJSON bool) error {
				routes, err := c.Routes()
				if err != nil {
					return err
				}
				return emit(w, asJSON, routes, func() { control.RenderRoutes(w, routes) })
			}),
		r.command("sessions", "live IKE SAs, their SPIs and how long since each peer last answered",
			func(c *control.Client, w io.Writer, asJSON bool) error {
				sessions, err := c.Sessions()
				if err != nil {
					return err
				}
				return emit(w, asJSON, sessions, func() { control.RenderSessions(w, sessions) })
			}),
		r.command("peers", "who this node dials, from the config file or from the registry, and whether it got there",
			func(c *control.Client, w io.Writer, asJSON bool) error {
				peers, err := c.Peers()
				if err != nil {
					return err
				}
				return emit(w, asJSON, peers, func() { control.RenderPeers(w, peers) })
			}),
		versionCommand(r),
		licensesCommand(),
		completionCommand(root),
	)
	return root
}

// command builds one read-only subcommand from what it asks the daemon for and
// how it prints the answer. The five are written out at the call sites rather
// than generated, so the type each one gets is the type the compiler checked.
func (r *reader) command(use, short string, run func(*control.Client, io.Writer, bool) error) *cobra.Command {
	cmd := &cobra.Command{
		Use:   use,
		Short: short,
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			return run(control.Dial(r.socket), cmd.OutOrStdout(), r.asJSON)
		},
	}
	r.flags(cmd)
	return cmd
}

// flags is the pair every read shares. They are per command rather than
// persistent on the root, because --control means "bind here" to the daemon
// and "read here" to everything else, and --json is meaningless to the daemon.
func (r *reader) flags(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringVar(&r.socket, "control", control.DefaultSocket, "path to the daemon's control socket")
	f.BoolVar(&r.asJSON, "json", false, "print the wire form instead of a table")
}

// versionCommand prints the version this binary was built from, and with
// --daemon the one the node on the other end of the socket is running. The two
// differ for exactly as long as an upgraded file waits for a restart, which is
// the window a fleet conversion spends every node in.
func versionCommand(r *reader) *cobra.Command {
	var fromDaemon bool
	cmd := &cobra.Command{
		Use:   "version",
		Short: "the version this binary was built from, or with --daemon the running node's",
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if !fromDaemon {
				fmt.Fprintln(cmd.OutOrStdout(), version.String())
				return nil
			}
			status, err := control.Dial(r.socket).Status()
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), status.Version)
			return nil
		},
	}
	cmd.Flags().BoolVar(&fromDaemon, "daemon", false, "ask the running node rather than reporting this binary")
	cmd.Flags().StringVar(&r.socket, "control", control.DefaultSocket, "path to the daemon's control socket")
	return cmd
}

// noArguments refuses a stray word. cobra.NoArgs reports it as an unknown
// command, which sends somebody who typed one argument too many looking for a
// subcommand that was never the problem.
func noArguments(cmd *cobra.Command, args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("%s takes no arguments, got %q", cmd.CommandPath(), args[0])
	}
	return nil
}

// emit writes one answer, as indented JSON or through its renderer. The JSON
// is re-encoded from the decoded value rather than passed through, so a client
// and a daemon that disagree about a field show that disagreement here rather
// than hiding it behind the daemon's own bytes.
func emit(w io.Writer, asJSON bool, value any, render func()) error {
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

// licensesCommand prints the notice every module linked into this binary
// requires a distribution to carry. It is a subcommand rather than a file
// beside the binary, because a binary gets distributed on its own and the
// obligation has to travel with it.
func licensesCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "licenses",
		Short: "print the license of every module linked into this binary",
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			_, err := io.WriteString(cmd.OutOrStdout(), notices.ThirdParty)
			return err
		},
	}
}
