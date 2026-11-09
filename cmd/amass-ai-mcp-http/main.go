// SPDX-License-Identifier: Apache-2.0
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/mcp"
	"github.com/owasp-amass/amass/v5/internal/ai/oamrepo"
	"github.com/owasp-amass/amass/v5/internal/tools"
)

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "amass-ai-mcp-http:", err)
		os.Exit(1)
	}
}
func run() error {
	cfgFile := flag.String("config", "/.config/amass/config.yaml", "Existing Amass configuration")
	addr := flag.String("listen", "0.0.0.0:8090", "Internal MCP HTTP listener")
	flag.Parse()
	token := os.Getenv("AMASS_AI_MCP_TOKEN")
	if len(token) < 32 {
		return errors.New("AMASS_AI_MCP_TOKEN must be a strong random secret (at least 32 characters)")
	}
	cfg := config.NewConfig()
	if err := config.AcquireConfig("", *cfgFile, cfg); err != nil {
		return fmt.Errorf("load Amass config: %w", err)
	}
	repo := tools.OpenGraphDatabase(cfg)
	if repo == nil {
		return errors.New("unable to open OAM database")
	}
	defer func() { _ = repo.Close() }()
	server := mcp.NewHTTPServer(ai.ToolRunner{Graph: oamrepo.Adapter{Repo: repo, Neo4jDatabase: oamrepo.Neo4jDatabaseName(cfg)}, Catalog: oamrepo.Catalog{}, Limits: ai.DefaultLimits()}, token)
	httpServer := &http.Server{Addr: *addr, Handler: server.Handler(), ReadHeaderTimeout: 5 * time.Second, MaxHeaderBytes: 16 << 10}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		<-ctx.Done()
		timeout, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = httpServer.Shutdown(timeout)
	}()
	fmt.Fprintln(os.Stderr, "mcp: authenticated read-only HTTP listener enabled")
	err := httpServer.ListenAndServe()
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}
