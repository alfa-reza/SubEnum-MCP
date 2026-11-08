// Command subenum is a stdio MCP server for v1.0.0 subdomain name
// enumeration. stdout carries only MCP framing; all logs go to stderr.
package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/server"
)

const serverVersion = "1.0.0"

func main() {
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo}))

	cfg, err := server.LoadConfig(os.Getenv)
	if err != nil {
		logger.Error("invalid configuration", "err", err)
		os.Exit(1)
	}
	app, err := server.NewApp(cfg, logger)
	if err != nil {
		logger.Error("server startup failed", "err", err)
		os.Exit(1)
	}
	defer func() {
		if err := app.Close(); err != nil {
			logger.Error("store close failed", "err", err)
		}
	}()
	root := app.Root()
	if root == "" {
		root = "unpinned (pins at first start_run)"
	}
	logger.Info("subenum-mcp starting",
		"scope_root", root,
		"data_dir", app.DataDir(),
		"version", serverVersion,
	)

	srv := mcp.NewServer(&mcp.Implementation{Name: "subenum-mcp", Version: serverVersion}, &mcp.ServerOptions{
		Instructions: `subenum-mcp enumerates subdomain NAMES for exactly one registrable-domain scope per server process. ` +
			`Call start_run with scope_root as your first tool (for example "bmkg.go.id", only a scope you are authorized to test); the first call pins the process to that root. ` +
			`Apex is never in scope. Real, hash-verified backends (subfinder, alterx, dnsx) run by default and fail with a clear error if binaries are missing or do not match compiled release hashes. ` +
			`For large resolves pass timeout_seconds (up to 300) and paginate with host_offset/host_limit; the AlterX candidate generator is capped at 5000. ` +
			`no_answer does not imply NXDOMAIN. No HTTP/TLS probing or exploitation is provided. Stay within the authorized program scope at all times.`,
	})
	app.Register(srv)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "subenum-mcp stopped: %v\n", err)
		os.Exit(1)
	}
}
