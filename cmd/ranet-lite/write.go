package main

import (
	"maps"
	"slices"
	"strings"

	"github.com/spf13/cobra"

	"github.com/NickCao/ranet-lite/control"
)

// This file is the write half of the command tree: the verbs that act on a
// running node rather than reading one.
//
// None of them changes the node's configuration, which keeps its two entry
// points, the file and SIGHUP. What each acts on is operational state the file
// already decides, so the socket's mode stays the whole authorization story;
// the control package doc holds the argument and the line a fifth verb would
// have to stay inside.

// writeCommands is the four verbs, which the root adds after the reads so the
// usage lists what a node answers before what it does.
func (r *reader) writeCommands() []*cobra.Command {
	return []*cobra.Command{
		r.subsystemCommand("disable", "stop a subsystem until it is enabled again or the node restarts", false),
		r.subsystemCommand("enable", "start a subsystem somebody disabled", true),
		r.redialCommand(),
		r.rekeyCommand(),
		r.reloadCommand(),
	}
}

// subsystemCommand builds disable and enable, which differ only in the state
// they ask for. The argument is completed from the closed set rather than from
// the daemon, because the set is the same on every node and a completion that
// needed a running one would offer nothing where it is most wanted.
func (r *reader) subsystemCommand(use, short string, on bool) *cobra.Command {
	cmd := &cobra.Command{
		Use:       use + " <" + strings.Join(control.SubsystemNames(), "|") + ">",
		Short:     short,
		Args:      cobra.ExactArgs(1),
		ValidArgs: control.SubsystemNames(),
		RunE: func(cmd *cobra.Command, args []string) error {
			client, subsystem := control.Dial(r.socket), control.Subsystem(args[0])
			ask := client.Disable
			if on {
				ask = client.Enable
			}
			result, err := ask(subsystem)
			return r.report(cmd, result, err)
		},
	}
	r.flags(cmd)
	return cmd
}

// redialCommand answers a peer holding a session this node no longer has. The
// butte cutover measured what that costs: one peer carried a dead session for
// sixteen minutes and came back only when its own daemon was reloaded by hand.
func (r *reader) redialCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:               "redial <peer>",
		Short:             "drop the sessions held for a peer and dial it again now rather than after the reconnect delay",
		Args:              cobra.ExactArgs(1),
		ValidArgsFunction: r.completePeers,
		RunE: func(cmd *cobra.Command, args []string) error {
			result, err := control.Dial(r.socket).Redial(args[0])
			return r.report(cmd, result, err)
		},
	}
	r.flags(cmd)
	return cmd
}

// rekeyCommand replaces a Child SA without waiting for its own schedule.
func (r *reader) rekeyCommand() *cobra.Command {
	var all bool
	cmd := &cobra.Command{
		Use:   "rekey [peer]",
		Short: "replace the child SA of one peer's sessions, or with --all of every session",
		// The peer and --all are exclusive, and the daemon says so as well:
		// this is the local half, so a command line that names neither is
		// answered without a round trip.
		Args: func(cmd *cobra.Command, args []string) error {
			if all {
				return noArguments(cmd, args)
			}
			return cobra.ExactArgs(1)(cmd, args)
		},
		ValidArgsFunction: r.completePeers,
		RunE: func(cmd *cobra.Command, args []string) error {
			peer := ""
			if !all {
				peer = args[0]
			}
			result, err := control.Dial(r.socket).Rekey(peer, all)
			return r.report(cmd, result, err)
		},
	}
	cmd.Flags().BoolVar(&all, "all", false, "rekey every session this node holds rather than one peer's")
	r.flags(cmd)
	return cmd
}

// reloadCommand is SIGHUP over the socket, so a supervisor is not the only way
// to ask and an operator on a node they did not start can ask at all.
func (r *reader) reloadCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "reload",
		Short: "re-read the configuration file and the trust document, as SIGHUP does",
		Args:  noArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			result, err := control.Dial(r.socket).Reload()
			return r.report(cmd, result, err)
		},
	}
	r.flags(cmd)
	return cmd
}

// report prints one verb's answer, as the wire form under --json and as the
// sentence otherwise. The error goes back untouched, because the daemon's
// refusals already name what this node does not run.
func (r *reader) report(cmd *cobra.Command, result control.Result, err error) error {
	if err != nil {
		return err
	}
	w := cmd.OutOrStdout()
	return emit(w, r.asJSON, result, func() { control.RenderResult(w, result) })
}

// completePeers offers the peers this node dials and the peers it holds a
// session with, which between them cover everything redial and rekey act on.
// A daemon that cannot be reached offers nothing rather than an error: a
// completion that wrote one would put it in the middle of a command line.
func (r *reader) completePeers(_ *cobra.Command, args []string, toComplete string) ([]cobra.Completion, cobra.ShellCompDirective) {
	if len(args) > 0 {
		return nil, cobra.ShellCompDirectiveNoFileComp
	}
	client := control.Dial(r.socket)
	named := make(map[string]struct{})
	if peers, err := client.Peers(); err == nil {
		for _, peer := range peers {
			named[peer.Organization+"/"+peer.CommonName] = struct{}{}
		}
	}
	// The sessions as well, because a peer that only dials this node has no
	// entry in the peers list and is exactly the peer a redial is for.
	if sessions, err := client.Sessions(); err == nil {
		for _, session := range sessions {
			if session.Peer != "" {
				named[session.Peer] = struct{}{}
			}
		}
	}
	out := make([]cobra.Completion, 0, len(named))
	for _, name := range slices.Sorted(maps.Keys(named)) {
		if strings.HasPrefix(name, toComplete) {
			out = append(out, name)
		}
	}
	return out, cobra.ShellCompDirectiveNoFileComp
}
