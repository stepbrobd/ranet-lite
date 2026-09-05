// Command ranet-lite connects a real TUN device to a ranet mesh through
// userspace IKEv2/ESP and an embedded Babel stub. Address and kernel route
// configuration are external; Babel exchanges control packets inside ESP.
package main

import (
	"context"
	"flag"
	"log"
	"log/slog"
	"net/http"
	_ "net/http/pprof"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/NickCao/ranet-lite/internal/client"
	"github.com/NickCao/ranet-lite/internal/config"
)

func main() {
	configPath := flag.String("config", "/etc/ranet-lite/config.yaml", "path to the ranet-lite config file")
	pprofAddr := flag.String("pprof", "", "if set, serve net/http/pprof on this address (e.g. 127.0.0.1:6060) for profiling — CPU: /debug/pprof/profile, flamegraph: go tool pprof -http=:8081 'http://<addr>/debug/pprof/profile?seconds=30'")
	contentionProfiles := flag.Bool("contention-profiles", false, "record every mutex and blocking event while pprof is enabled (high overhead)")
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
	log.Printf("tun device %s ready with %d queues; configure its addresses and kernel routes externally", mesh.Name, mesh.QueueCount())

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

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

	if err := node.Run(ctx); err != nil && ctx.Err() == nil {
		log.Printf("client: %v", err)
	}
}
