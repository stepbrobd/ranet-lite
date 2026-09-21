// Command ranet-lite connects a real TUN device to a ranet mesh through
// userspace IKEv2/ESP and an embedded Babel speaker. Babel exchanges control
// packets inside ESP. Address and route configuration are external unless the
// file carries a cap.table block, which turns the route reconciler on.
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
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"

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
	f.StringVarP(&o.configPath, "config", "c", "/etc/ranet-lite/config.toml", "path to the ranet-lite config file, .toml, .yaml, .yml or .json")
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

	cfg, err := config.Load(*configPath)
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
				if err := node.Reload(*configPath); err != nil {
					log.Printf("reload: %v", err)
				}
			}
		}
	}()

	// The reconciler is one capability, so a deployment that configures its
	// device externally writes no cap.table and gets none of this.
	var reconciler sync.WaitGroup
	if table := cfg.Cap.Table; table != nil {
		// What the file could not say: the device the mesh actually got, the
		// addresses the transport has to keep reaching, and the prefixes
		// cap.route announces, which assign_announced puts on that device.
		runtime := kernel.Runtime{
			Interface: mesh.Name,
			Underlay:  node.Underlay,
			Announced: cfg.Routes().Announced(),
		}
		routes, err := kernel.New(*table, runtime, mesh.Routes)
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

// kernelStatus is the reconciler as the control surface reports it: what it
// was configured to own and what its last pass did. The configuration half
// comes from the capability the reconciler resolved rather than from the file,
// so the defaults it filled in are the ones reported.
func kernelStatus(routes *kernel.Reconciler) control.KernelStatus {
	table, stats := routes.Table(), routes.Stats()
	return control.KernelStatus{
		Enabled:   true,
		Where:     routes.Where(),
		Table:     uint32(table.ID),
		Protocol:  table.Proto,
		Metric:    table.Metric,
		VRF:       table.Name(),
		PassAt:    stats.At,
		Installed: stats.Installed,
		Skipped:   stats.Skipped,
		Added:     stats.Added,
		Removed:   stats.Removed,
		Err:       stats.Err,
	}
}
