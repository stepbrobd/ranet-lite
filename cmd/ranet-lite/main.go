// Command ranet-lite connects a real TUN device to a ranet mesh through
// userspace IKEv2/ESP and an embedded Babel speaker. Babel exchanges control
// packets inside ESP. Address and kernel route configuration are external
// unless the kernel block in the config file turns the reconciler on.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/NickCao/ranet-lite/internal/client"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/kernel"
)

func main() { os.Exit(run()) }

// options is the command line after parsing.
type options struct {
	configPath         string
	pprofAddr          string
	metricsAddr        string
	contentionProfiles bool
	level              slog.Level
}

// parseOptions reads the command line and refuses what it cannot act on. It
// takes the arguments rather than reading them from the process, and returns
// an error rather than calling log.Fatal, so that both refusals are reachable
// from a test: log.Fatal is os.Exit, which a test cannot observe.
func parseOptions(args []string, usage io.Writer) (options, error) {
	fs := flag.NewFlagSet("ranet-lite", flag.ContinueOnError)
	fs.SetOutput(usage)
	var o options
	fs.StringVar(&o.configPath, "config", "/etc/ranet-lite/config.yaml", "path to the ranet-lite config file")
	fs.StringVar(&o.pprofAddr, "pprof", "", "if set, serve net/http/pprof on this address (e.g. 127.0.0.1:6060) for profiling, CPU at /debug/pprof/profile and flamegraph at go tool pprof -http=:8081 'http://<addr>/debug/pprof/profile?seconds=30'")
	fs.BoolVar(&o.contentionProfiles, "contention-profiles", false, "record every mutex and blocking event while pprof is enabled (high overhead)")
	fs.StringVar(&o.metricsAddr, "metrics", "", "if set, serve Prometheus metrics on this address (e.g. 127.0.0.1:9669) at /metrics")
	logLevel := fs.String("log-level", "info", "minimum log level: debug, info, warn, or error")
	if err := fs.Parse(args); err != nil {
		return options{}, err
	}
	if fs.NArg() != 0 {
		// A missing dash is the way this happens: `ranet-lite config.yaml`
		// otherwise starts silently against the default path.
		return options{}, fmt.Errorf("unexpected argument %q: the config path is given with -config", fs.Arg(0))
	}
	if err := o.level.UnmarshalText([]byte(*logLevel)); err != nil {
		return options{}, fmt.Errorf("invalid -log-level %q: %w", *logLevel, err)
	}
	return o, nil
}

// run is main's body so that every deferred close runs before the process
// exits with a status. A failure reported only in the log and then exited zero
// tells a supervisor the node stopped cleanly when it did not, and the route
// withdrawal at shutdown is one of the things that reports this way.
func run() int {
	opts, err := parseOptions(os.Args[1:], os.Stderr)
	if err != nil {
		log.Fatal(err)
	}
	configPath, pprofAddr := &opts.configPath, &opts.pprofAddr
	metricsAddr, contentionProfiles := &opts.metricsAddr, &opts.contentionProfiles
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: opts.level})))

	// Set by anything that fails after the point where log.Fatal would skip
	// the deferred cleanup. run returns nonzero if any of them did.
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
		log.Fatal(err)
	}
	node, err := client.New(cfg)
	if err != nil {
		log.Fatal(err)
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
	// again has nothing to press; the second signal is what answers that.
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

	// The reconciler is opt-in, so an existing deployment keeps configuring
	// the device externally.
	var reconciler sync.WaitGroup
	if cfg.Kernel.Enabled {
		// log.Fatal is os.Exit, which runs no deferred function, so the node
		// opened above is closed by hand here. These two are the failures a
		// misconfigured node actually hits.
		fatal := func(err error) {
			node.Close()
			log.Fatal(err)
		}
		kernelCfg, err := kernelConfig(cfg, mesh.Name)
		if err != nil {
			fatal(err)
		}
		routes, err := kernel.New(kernelCfg, mesh.Routes)
		if err != nil {
			fatal(err)
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
	} else {
		log.Printf("tun device %s ready with %d queues, configure its addresses and kernel routes externally",
			mesh.Name, mesh.QueueCount())
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
// second. Both come off one channel in order, which is what keeps a signal
// from reaching nobody; see the registration above.
func watchSignals(signals <-chan os.Signal, cancel context.CancelFunc, force func()) {
	<-signals
	cancel()
	<-signals
	log.Print("second signal, exiting without finishing shutdown")
	force()
}

// kernelConfig resolves the config file's kernel block against the device the
// mesh actually got and the prefixes this node originates. The addresses are
// parsed here rather than in config.Load, so the reconciler's own validation
// in kernel.New stays the single place that decides what it accepts.
func kernelConfig(cfg *config.Config, device string) (kernel.Config, error) {
	out := kernel.Config{
		Interface: device,
		Table:     cfg.Kernel.Table,
		Protocol:  cfg.Kernel.Protocol,
		Metric:    cfg.Kernel.Metric,
		VRF:       cfg.Kernel.VRF,
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
