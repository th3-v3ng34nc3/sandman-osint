package main

import (
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"

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

	if err := http.ListenAndServe(cfg.ListenAddr, mux); err != nil {
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
