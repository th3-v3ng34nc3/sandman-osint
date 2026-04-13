package main

import (
	"context"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"sandman-osint/internal/ai"
	"sandman-osint/internal/config"
	"sandman-osint/internal/engine"
	"sandman-osint/internal/sources"
	"sandman-osint/internal/sse"
	"sandman-osint/web"
)

func main() {
	addr := flag.String("addr", "", "listen address (default :8080, overrides PORT env)")
	torFlag := flag.Bool("tor", false, "enable Tor proxy routing")
	torAddr := flag.String("tor-addr", "", "Tor SOCKS5 address (default 127.0.0.1:9050)")
	flag.Parse()

	cfg := config.Load()

	if *addr != "" {
		cfg.ListenAddr = normalizeAddr(*addr)
	}
	if *torFlag {
		cfg.Tor.Enabled = true
	}
	if *torAddr != "" {
		cfg.Tor.SOCKSAddr = *torAddr
	}

	clients := sources.BuildClients(cfg)
	broker := sse.NewBroker()
	store := engine.NewStore()
	analyzer := ai.NewAnalyzer(cfg)
	eng := engine.New(cfg, clients, broker, store, analyzer)
	srv := web.NewServer(cfg, eng, broker, store)

	mux := http.NewServeMux()
	srv.RegisterRoutes(mux)

	fmt.Printf("\n  ███████╗ █████╗ ███╗   ██╗██████╗ ███╗   ███╗ █████╗ ███╗   ██╗\n")
	fmt.Printf("  ██╔════╝██╔══██╗████╗  ██║██╔══██╗████╗ ████║██╔══██╗████╗  ██║\n")
	fmt.Printf("  ███████╗███████║██╔██╗ ██║██║  ██║██╔████╔██║███████║██╔██╗ ██║\n")
	fmt.Printf("  ╚════██║██╔══██║██║╚██╗██║██║  ██║██║╚██╔╝██║██╔══██║██║╚██╗██║\n")
	fmt.Printf("  ███████║██║  ██║██║ ╚████║██████╔╝██║ ╚═╝ ██║██║  ██║██║ ╚████║\n")
	fmt.Printf("  ╚══════╝╚═╝  ╚═╝╚═╝  ╚═══╝╚═════╝ ╚═╝     ╚═╝╚═╝  ╚═╝╚═╝  ╚═══╝\n")
	fmt.Printf("  sandman osint\n\n")

	slog.Info("server started", "url", "http://localhost"+cfg.ListenAddr)
	if cfg.Tor.Enabled {
		slog.Info("tor proxy enabled", "addr", cfg.Tor.SOCKSAddr)
	}

	httpSrv := &http.Server{Addr: cfg.ListenAddr, Handler: mux}

	// Graceful shutdown on SIGINT / SIGTERM
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-quit
		slog.Info("shutting down…")
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		httpSrv.Shutdown(ctx)
	}()

	if err := httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("server error", "err", err)
		os.Exit(1)
	}
}

func normalizeAddr(s string) string {
	if !strings.HasPrefix(s, ":") {
		return ":" + s
	}
	return s
}
