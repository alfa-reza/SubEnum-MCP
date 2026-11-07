// Command subenum-mcp is a stdio MCP server for v1.0.0 subdomain name
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
	defer app.Store().Close()
	logger.Info("subenum-mcp starting",
		"scope_root", app.Root(),
		"data_dir", app.DataDir(),
		"mode", "fixture-by-default",
		"external", "requires explicit enable, matching authorization, pinned binaries, and separate live opt-in for network tools",
	)

	srv := mcp.NewServer(&mcp.Implementation{Name: "subenum-mcp", Version: serverVersion}, nil)
	app.Register(srv)

	if err := srv.Run(context.Background(), &mcp.StdioTransport{}); err != nil {
		fmt.Fprintf(os.Stderr, "subenum-mcp stopped: %v\n", err)
		os.Exit(1)
	}
}
