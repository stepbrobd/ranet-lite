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
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"net/netip"
	"os"
	"os/signal"
	"runtime"
	"sync"
	"syscall"
	"time"

	"github.com/NickCao/ranet-lite/internal/client"
	"github.com/NickCao/ranet-lite/internal/config"
	"github.com/NickCao/ranet-lite/internal/kernel"
)

func main() {
	configPath := flag.String("config", "/etc/ranet-lite/config.yaml", "path to the ranet-lite config file")
	pprofAddr := flag.String("pprof", "", "if set, serve net/http/pprof on this address (e.g. 127.0.0.1:6060) for profiling, CPU at /debug/pprof/profile and flamegraph at go tool pprof -http=:8081 'http://<addr>/debug/pprof/profile?seconds=30'")
	contentionProfiles := flag.Bool("contention-profiles", false, "record every mutex and blocking event while pprof is enabled (high overhead)")
	metricsAddr := flag.String("metrics", "", "if set, serve Prometheus metrics on this address (e.g. 127.0.0.1:9669) at /metrics")
	logLevel := flag.String("log-level", "info", "minimum log level: debug, info, warn, or error")
	flag.Parse()
	var level slog.Level
	if err := level.UnmarshalText([]byte(*logLevel)); err != nil {
		log.Fatalf("invalid -log-level %q: %v", *logLevel, err)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level})))

	if *pprofAddr != "" {
		if *contentionProfiles {
			runtime.SetMutexProfileFraction(1)
			runtime.SetBlockProfileRate(1)
		}
		go func() {
			log.Printf("pprof listening on http://%s/debug/pprof/", *pprofAddr)
			if err := http.ListenAndServe(*pprofAddr, nil); err != nil {
				log.Printf("pprof: %v", err)
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
			}
		}()
		defer server.Close()
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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
		kernelCfg, err := kernelConfig(cfg, mesh.Name)
		if err != nil {
			log.Fatal(err)
		}
		routes, err := kernel.New(kernelCfg, mesh.Routes)
		if err != nil {
			log.Fatal(err)
		}
		reconciler.Go(func() {
			if err := routes.Run(ctx); err != nil {
				log.Printf("kernel: %v", err)
			}
		})
		log.Printf("tun device %s ready with %d queues, reconciling its routes into table %d",
			mesh.Name, mesh.QueueCount(), kernelCfg.Table)
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
	}
	// Whichever side stopped first, stop the other, then let the reconciler
	// finish withdrawing before the process exits.
	cancel()
	reconciler.Wait()
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
