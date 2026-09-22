package main

import (
	"fmt"
	"net/netip"
	"time"

	"github.com/spf13/cobra"

	"github.com/NickCao/ranet-lite/control"
	"github.com/NickCao/ranet-lite/internal/version"
)

// This file is the commands that ask a question of what the read paths return
// rather than printing one of them: which prefix covers an address, which
// addresses this node holds, which defaults the mesh offers, and everything at
// once for a bug report. Each one reads and nothing more, so none of them adds
// anything the daemon has to serve.

// queryCommands are added beside the plain reads.
func (r *reader) queryCommands() []*cobra.Command {
	return []*cobra.Command{
		r.whoisCommand(),
		r.addressCommand(),
		r.exitNodeCommand(),
		r.bugreportCommand(),
	}
}

// whoisCommand answers where an address goes, by longest prefix match over the
// mesh route table.
//
// It names the peer this node reaches the prefix through rather than the node
// that originates it. Babel carries a router id and no name, and this tree
// gives each speaker a random one, so the origin is nameable only where it is
// a neighbor. The router id is printed as it arrives, which at least tells two
// origins apart and survives a peer's restart being visible as a change.
func (r *reader) whoisCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whois <address>",
		Short: "which prefix covers an address and which peer this node reaches it through",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			address, err := netip.ParseAddr(args[0])
			if err != nil {
				return fmt.Errorf("whois takes an address, not %q: %w", args[0], err)
			}
			routes, err := control.Dial(r.socket).Routes()
			if err != nil {
				return err
			}
			covering := control.Covering(routes, address)
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, covering, func() { control.RenderWhois(w, address, covering) })
		},
	}
	r.flags(cmd)
	return cmd
}

// addressCommand prints this node's own mesh addresses, one per line, which is
// `tailscale ip`. A node whose addresses are assigned by cap.table announces
// the same prefixes, so one answer serves both.
func (r *reader) addressCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "ip",
		Short: "this node's mesh addresses, one per line",
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			status, err := control.Dial(r.socket).Status()
			if err != nil {
				return err
			}
			addresses := control.MeshAddresses(status)
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, addresses, func() { control.RenderAddresses(w, addresses) })
		},
	}
	r.flags(cmd)
	return cmd
}

// exitNodeCommand is a parent, so that whatever else an exit grows a verb for
// later has a place to go and `exit-node` on its own prints what it can do.
func (r *reader) exitNodeCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "exit-node",
		Short: "the nodes advertising a default, and which one this node takes",
	}
	list := &cobra.Command{
		Use:   "list",
		Short: "list the defaults the mesh advertises and say which this node would take",
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			routes, err := control.Dial(r.socket).Routes()
			if err != nil {
				return err
			}
			defaults := control.Defaults(routes)
			w := cmd.OutOrStdout()
			return emit(w, r.asJSON, defaults, func() { control.RenderExitNodes(w, defaults) })
		},
	}
	r.flags(list)
	cmd.AddCommand(list)
	return cmd
}

// bugreport is every subsystem in one object, for pasting into a report. The
// shape is this command's own rather than part of the wire, because nothing
// serves it: a client assembles it out of the reads it could get.
type bugreport struct {
	Binary    string             `json:"binary"`
	Socket    string             `json:"socket"`
	TakenAt   time.Time          `json:"taken_at"`
	Status    *control.Status    `json:"status,omitempty"`
	Neighbors []control.Neighbor `json:"neighbors,omitempty"`
	Routes    []control.Route    `json:"routes,omitempty"`
	Sessions  []control.Session  `json:"sessions,omitempty"`
	Peers     []control.Peer     `json:"peers,omitempty"`
	Metrics   string             `json:"metrics,omitempty"`
	// Refused names the reads that did not answer, in the order they were
	// asked. A report is worth having from a node that is half up, so one
	// failing read leaves its own line here instead of replacing the report
	// with an error and sending the operator back to collect the rest by hand.
	Refused []string `json:"refused,omitempty"`
}

// bugreportCommand collects every read into one blob. It takes no --json,
// because JSON is the only form it has: the blob is for pasting whole rather
// than for reading down a column.
func (r *reader) bugreportCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "bugreport",
		Short: "every subsystem in one json blob, for pasting into a report",
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client := control.Dial(r.socket)
			report := bugreport{Binary: version.String(), Socket: client.Path(), TakenAt: time.Now()}
			collect(&report.Refused, "status", func() error {
				status, err := client.Status()
				report.Status = &status
				return err
			})
			collect(&report.Refused, "neighbors", func() (err error) {
				report.Neighbors, err = client.Neighbors()
				return err
			})
			collect(&report.Refused, "routes", func() (err error) {
				report.Routes, err = client.Routes()
				return err
			})
			collect(&report.Refused, "sessions", func() (err error) {
				report.Sessions, err = client.Sessions()
				return err
			})
			collect(&report.Refused, "peers", func() (err error) {
				report.Peers, err = client.Peers()
				return err
			})
			collect(&report.Refused, "metrics", func() (err error) {
				report.Metrics, err = client.Metrics()
				return err
			})
			// A status that never arrived is dropped rather than reported as a
			// node with no name and no counts, which reads as a running node
			// that lost them.
			if report.Status != nil && report.Status.Version == "" {
				report.Status = nil
			}
			return emit(cmd.OutOrStdout(), true, report, nil)
		},
	}
	cmd.Flags().StringVar(&r.socket, "control", control.DefaultSocket, "path to the daemon's control socket")
	return cmd
}

// collect runs one read and records its failure instead of returning it, so a
// node that answers five of six still produces a report.
func collect(refused *[]string, name string, read func() error) {
	if err := read(); err != nil {
		*refused = append(*refused, name+": "+err.Error())
	}
}
