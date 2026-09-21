// Command ranet-lite connects a real TUN device to a ranet mesh through
// userspace IKEv2/ESP and an embedded Babel speaker. Babel exchanges control
// packets inside ESP. Address and kernel route configuration are external
// unless the kernel block in the config file turns the reconciler on.
//
// `ranet-lite daemon` is the node. Every other subcommand reads a running
// one's control socket; see cli.go.
package main

import (
	"context"
	"errors"
	"fmt"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/NickCao/ranet-lite/internal/client"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/control"
	"github.com/NickCao/ranet-lite/internal/kernel"
)

// main runs the command tree and turns what it returns into a process status.
// A daemon that refused to start has already said why through the handler an
// operator's log level selects, so its status comes back as an exitCode and is
// not written a second time.
func main() {
	if err := newRoot().Execute(); err != nil {
		var code exitCode
		if errors.As(err, &code) {
			os.Exit(int(code))
		}
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// exitCode carries a process status out through cobra's error return, which is
// the only way back to main from a command body.
type exitCode int

func (e exitCode) Error() string { return fmt.Sprintf("exit status %d", int(e)) }

// options is the daemon's command line after parsing.
type options struct {
	configPath         string
	registryPath       string
	privateKeyPath     string
	fullMesh           bool
	pprofAddr          string
	metricsAddr        string
	controlPath        string
	contentionProfiles bool
	level              slog.Level
}

// daemonCommand is the node itself. Its flags are its own rather than the
// root's: a reader's --control names a socket to read and this one names a
// socket to bind, and the two would share a description that fits neither.
func daemonCommand() *cobra.Command {
	var o options
	var logLevel string
	cmd := &cobra.Command{
		Use:   "daemon",
		Short: "run this node: IKEv2, ESP, the babel speaker and the optional route reconciler",
		Args:  noArguments,
		RunE: func(*cobra.Command, []string) error {
			if err := o.level.UnmarshalText([]byte(logLevel)); err != nil {
				return fmt.Errorf("invalid --log-level %q: %w", logLevel, err)
			}
			if code := runDaemon(o); code != 0 {
				return exitCode(code)
			}
			return nil
		},
	}
	f := cmd.Flags()
	f.StringVarP(&o.configPath, "config", "c", "/etc/ranet-lite/config.yaml", "path to the ranet-lite config file")
	f.StringVar(&o.registryPath, "registry", "", "path to registry.json, overriding the config file; ranet spells it this way and its own config carries no such field")
	f.StringVar(&o.privateKeyPath, "key", "", "path to the PKCS8 PEM Ed25519 private key, overriding the config file; ranet spells it this way and its own config carries no such field")
	f.BoolVar(&o.fullMesh, "full-mesh", false, "dial every node the registry names, as ranet does; its own config file has no field to ask for this")
	f.StringVar(&o.pprofAddr, "pprof", "", "if set, serve net/http/pprof on this address (e.g. 127.0.0.1:6060) for profiling, CPU at /debug/pprof/profile and flamegraph at go tool pprof -http=:8081 'http://<addr>/debug/pprof/profile?seconds=30'")
	f.BoolVar(&o.contentionProfiles, "contention-profiles", false, "record every mutex and blocking event while pprof is enabled (high overhead)")
	f.StringVar(&o.metricsAddr, "metrics", "", "if set, serve Prometheus metrics on this address (e.g. 127.0.0.1:9669) at /metrics")
	f.StringVar(&o.controlPath, "control", control.DefaultSocket, "unix socket serving the read-only control surface the other subcommands read; empty disables it")
	f.StringVar(&logLevel, "log-level", "info", "minimum log level: debug, info, warn, or error")
	return cmd
}

// refuseToStart reports a startup this node will not attempt, at the level an
// operator filters for. The standard logger writes through slog at INFO,
// which --log-level warn and above drop, so every refusal below was a process
// that exited 1 having written nothing at all.
func refuseToStart(err error) int {
	slog.Error("ranet-lite is not starting", "err", err)
	return 1
}

// runDaemon is the node's body, in a function of its own so that every
// deferred close runs before the process exits with a status. A failure
// reported only in the log and then exited zero tells a supervisor the node
// stopped cleanly when it did not, and the route withdrawal at shutdown is one
// of the things that reports this way.
func runDaemon(opts options) int {
	configPath, pprofAddr := &opts.configPath, &opts.pprofAddr
	metricsAddr, contentionProfiles := &opts.metricsAddr, &opts.contentionProfiles
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: opts.level})))

	// Set by anything that fails on a goroutine or after runDaemon has
	// committed to a clean shutdown. It returns nonzero if any of them did.
	var failed atomic.Bool

	if *pprofAddr != "" {
		if *contentionProfiles {
			runtime.SetMutexProfileFraction(1)
			runtime.SetBlockProfileRate(1)
		}
		go func() {
			log.Printf("pprof listening on http://%s/debug/pprof/", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("pprof: %v", err)
				failed.Store(true)
			}
		}()
	}

	cfg, err := config.Load(*configPath, opts.registryPath, opts.privateKeyPath, opts.fullMesh)
	if err != nil {
		return refuseToStart(err)
	}
	node, err := client.New(cfg)
	if err != nil {
		return refuseToStart(err)
	}
	defer node.Close()
	mesh := node.Mesh

	// A separate listener from pprof: a fleet node wants metrics scraped
	// without exposing a profiler, and a profiling run wants the profiler
	// without rewiring monitoring.
	if *metricsAddr != "" {
		mux := http.NewServeMux()
		mux.Handle("/metrics", node.MetricsHandler())
		server := &http.Server{Addr: *metricsAddr, Handler: mux}
		go func() {
			log.Printf("metrics listening on http://%s/metrics", *metricsAddr)
			if err := server.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
				log.Printf("metrics: %v", err)
				failed.Store(true)
			}
		}()
		defer server.Close()
	}

	// One registration and one reader, rather than signal.NotifyContext plus a
	// second channel registered after it cancels. Shutdown closes every
	// session with a grace period, withdraws the installed routes and waits
	// for every dialer, and while that is slow an operator pressing Ctrl-C
	// again has nothing to press; the second signal answers that.
	//
	// Registering the second channel only after the first signal leaves a
	// window in which a signal reaches nobody: NotifyContext has stopped
	// reading its own channel and the replacement does not exist yet. Two
	// signals with no gap lose the second there. Registering it up front
	// instead delivers the first signal to both, and then the first Ctrl-C
	// forces an exit rather than shutting down, which is the failure the
	// window was introduced to fix. Reading both from one channel in order has
	// neither: the first cancels, the second forces, and a burst of two is
	// held by the buffer.
	signals := make(chan os.Signal, 2)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(signals)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watchSignals(signals, cancel, func() { os.Exit(1) })

	// SIGHUP reconciles rather than restarts. The registry is rewritten every
	// time any node joins the mesh, and a restart to pick that up would drop
	// every SA this node is carrying.
	reload := make(chan os.Signal, 1)
	signal.Notify(reload, syscall.SIGHUP)
	defer signal.Stop(reload)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-reload:
				if err := node.Reload(*configPath, opts.registryPath, opts.privateKeyPath, opts.fullMesh); err != nil {
					log.Printf("reload: %v", err)
				}
			}
		}
	}()

	// The reconciler is opt-in, so an existing deployment keeps configuring
	// the device externally.
	var reconciler sync.WaitGroup
	if cfg.Kernel.Enabled {
		kernelCfg, err := kernelConfig(cfg, mesh.Name, node.Underlay)
		if err != nil {
			return refuseToStart(err)
		}
		routes, err := kernel.New(kernelCfg, mesh.Routes)
		if err != nil {
			return refuseToStart(err)
		}
		reconciler.Go(func() {
			// This error is the withdrawal failing as often as it is the
			// reconcile: routes left behind in the kernel after shutdown are
			// exactly what an operator must not be told was a clean exit.
			if err := routes.Run(ctx); err != nil {
				log.Printf("kernel: %v", err)
				failed.Store(true)
			}
		})
		// The table is read back from the reconciler rather than from the
		// config, which has not had its defaults applied yet and reads zero on
		// a platform that has no tables at all.
		log.Printf("tun device %s ready with %d queues, reconciling its routes into %s",
			mesh.Name, mesh.QueueCount(), routes.Where())
		node.SetKernelStatus(func() control.KernelStatus { return kernelStatus(routes) })
	} else {
		log.Printf("tun device %s ready with %d queues, configure its addresses and kernel routes externally",
			mesh.Name, mesh.QueueCount())
	}

	// The control socket is bound rather than served here, so a path an
	// operator named and this node cannot bind refuses the startup instead of
	// leaving a node nobody has a way to ask anything. The default path is the
	// one case that warns and carries on: it is on without being asked for, so
	// a node whose unit cannot reach /var/run would otherwise stop starting on
	// upgrade over a diagnostic it never requested. --control "" is the opt-out.
	if opts.controlPath != "" {
		listener, err := control.Listen(opts.controlPath)
		if err != nil && opts.controlPath == control.DefaultSocket {
			slog.Warn("running without a control socket, so the subcommands have nothing to read", "err", err)
		} else if err != nil {
			return refuseToStart(err)
		}
		if listener != nil {
			defer listener.Close()
			go func() {
				log.Printf("control socket listening on %s", opts.controlPath)
				if err := control.Serve(listener, node); err != nil {
					log.Printf("control: %v", err)
					failed.Store(true)
				}
			}()
		}
	}

	// The reconciler has to finish withdrawing while the TUN still exists,
	// and client.Run destroys it as soon as its own context is done. So the
	// mesh runs on a context canceled only once the reconciler has returned;
	// the signal context still stops both, just in that order.
	meshCtx, stopMesh := context.WithCancel(context.Background())
	defer stopMesh()
	go func() {
		<-ctx.Done()
		reconciler.Wait()
		stopMesh()
	}()

	// SIGUSR1 dumps the current mesh route table to the log — the fastest
	// way to see what babel has actually installed without wiring up a
	// separate debug endpoint. Route installs/retractions and neighbor
	// up/down transitions are also logged as they happen.
	dumpRoutes := make(chan os.Signal, 1)
	signal.Notify(dumpRoutes, syscall.SIGUSR1)
	defer signal.Stop(dumpRoutes)
	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			case <-dumpRoutes:
				routes := mesh.Routes.Debug()
				if len(routes) == 0 {
					log.Printf("routes: (none installed)")
					continue
				}
				log.Printf("routes:")
				for _, r := range routes {
					log.Printf("  %s", r)
				}
			}
		}
	}()

	if err := node.Run(meshCtx); err != nil && ctx.Err() == nil {
		log.Printf("client: %v", err)
		failed.Store(true)
	}
	// Whichever side stopped first, stop the other, then let the reconciler
	// finish withdrawing before the process exits.
	cancel()
	reconciler.Wait()
	if failed.Load() {
		return 1
	}
	return 0
}

// watchSignals starts the shutdown on the first signal and gives up on the
// second. Both come off one channel in order, which keeps a signal from
// reaching nobody; see the registration above.
func watchSignals(signals <-chan os.Signal, cancel context.CancelFunc, force func()) {
	<-signals
	cancel()
	<-signals
	log.Print("second signal, exiting without finishing shutdown")
	force()
}

// kernelRules turns the config file's rules into the reconciler's, resolving
// each one's address family. A rule that names neither a destination nor a
// source selects on a mark alone, which belongs to no family, so it says which
// one it is for; "both" is written once and installed twice, because that is
// what keeping an underlay out of a mesh table needs and writing it twice by
// hand is how one of the two goes missing.
//
// Everything the reconciler itself judges is left to Rule.validate, so the one
// place that decides what a rule may say is the one that installs it.
func kernelRules(rules []config.Rule) ([]kernel.Rule, error) {
	var out []kernel.Rule
	for _, rule := range rules {
		to, err := rulePrefix("to", rule.To)
		if err != nil {
			return nil, err
		}
		from, err := rulePrefix("from", rule.From)
		if err != nil {
			return nil, err
		}
		families, err := ruleFamilies(rule, to, from)
		if err != nil {
			return nil, err
		}
		for _, family := range families {
			out = append(out, kernel.Rule{
				Family:   family,
				To:       to,
				From:     from,
				FWMark:   rule.FWMark,
				FWMask:   rule.FWMask,
				Table:    uint32(rule.Table),
				Priority: rule.Priority,
			})
		}
	}
	return out, nil
}

// ruleFamilies is the families one configured rule installs for. An address
// already says which family it belongs to, so naming one as well is refused
// rather than silently resolved one way or the other.
func ruleFamilies(rule config.Rule, to, from netip.Prefix) ([]uint8, error) {
	addressed := to.IsValid() || from.IsValid()
	named := strings.ToLower(rule.Family)
	if addressed && named != "" {
		return nil, fmt.Errorf("config: kernel rule at priority %d names family %q and an address, which already says which family it is", rule.Priority, rule.Family)
	}
	if addressed {
		address := to.Addr()
		if !to.IsValid() {
			address = from.Addr()
		}
		if address.Is4() {
			return []uint8{kernel.FamilyIPv4}, nil
		}
		return []uint8{kernel.FamilyIPv6}, nil
	}
	switch named {
	case "ipv4":
		return []uint8{kernel.FamilyIPv4}, nil
	case "ipv6":
		return []uint8{kernel.FamilyIPv6}, nil
	case "both":
		return []uint8{kernel.FamilyIPv4, kernel.FamilyIPv6}, nil
	case "":
		return nil, fmt.Errorf("config: kernel rule at priority %d selects on a mark alone, so it has to name family: ipv4, ipv6 or both", rule.Priority)
	}
	return nil, fmt.Errorf("config: kernel rule at priority %d: family %q is not ipv4, ipv6 or both", rule.Priority, rule.Family)
}

func rulePrefix(name, raw string) (netip.Prefix, error) {
	if raw == "" {
		return netip.Prefix{}, nil
	}
	prefix, err := netip.ParsePrefix(raw)
	if err != nil {
		return netip.Prefix{}, fmt.Errorf("config: kernel rule %s %q: %w", name, raw, err)
	}
	return prefix, nil
}

// kernelStatus is the reconciler as the control surface reports it: what it
// was configured to own and what its last pass did. The configuration half
// comes from the resolved kernel.Config rather than from the config file, so
// the defaults the reconciler filled in are the ones reported.
func kernelStatus(routes *kernel.Reconciler) control.KernelStatus {
	cfg, stats := routes.Config(), routes.Stats()
	return control.KernelStatus{
		Enabled:   true,
		Where:     routes.Where(),
		Table:     cfg.Table,
		Protocol:  cfg.Protocol,
		Metric:    cfg.Metric,
		VRF:       cfg.VRF,
		PassAt:    stats.At,
		Installed: stats.Installed,
		Skipped:   stats.Skipped,
		Added:     stats.Added,
		Removed:   stats.Removed,
		Err:       stats.Err,
	}
}

// kernelConfig resolves the config file's kernel block against the device the
// mesh actually got and the prefixes this node originates. The addresses are
// parsed here rather than in config.Load, so the reconciler's own validation
// in kernel.New stays the single place that decides what it accepts.
func kernelConfig(cfg *config.Config, device string, underlay func() []netip.Addr) (kernel.Config, error) {
	rules, err := kernelRules(cfg.Kernel.Rules)
	if err != nil {
		return kernel.Config{}, err
	}
	out := kernel.Config{
		Interface: device,
		Underlay:  underlay,
		Table:     cfg.Kernel.Table,
		Protocol:  cfg.Kernel.Protocol,
		Metric:    cfg.Kernel.Metric,
		VRF:       cfg.Kernel.VRF,
		CreateVRF: cfg.Kernel.CreateVRF,
		Rules:     rules,
	}
	if cfg.Kernel.ReconcileInterval != nil {
		out.ReconcileInterval = time.Duration(*cfg.Kernel.ReconcileInterval)
	}
	if raw := cfg.Kernel.PrefSrc4; raw != "" {
		address, err := netip.ParseAddr(raw)
		if err != nil {
			return kernel.Config{}, fmt.Errorf("config: kernel.prefsrc4 %q: %w", raw, err)
		}
		out.PrefSrc4 = address
	}
	addresses, err := cfg.KernelAddresses()
	if err != nil {
		return kernel.Config{}, err
	}
	out.Addresses = addresses
	return out, nil
}
