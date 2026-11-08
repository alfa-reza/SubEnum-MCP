package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/store"
)

// ---- export_results ----

type ExportIn struct {
	RunID  string `json:"run_id,omitempty" jsonschema:"run to export; empty uses the latest run"`
	Format string `json:"format" jsonschema:"required export format: jsonl or csv"`
	Folder string `json:"folder,omitempty" jsonschema:"optional managed folder name using lowercase letters, numbers, underscore or hyphen; empty selects export-<timestamp>"`
}

type ExportOut struct {
	Result        store.ExportResult `json:"result"`
	ScopeFiltered bool               `json:"scope_filtered"`
}

func (a *App) handleExport(ctx context.Context, req *mcp.CallToolRequest, in ExportIn) (*mcp.CallToolResult, ExportOut, error) {
	if err := a.ensurePinned(); err != nil {
		return nil, ExportOut{}, err
	}
	run, err := a.runForRead(in.RunID)
	if err != nil {
		return nil, ExportOut{}, err
	}
	format := strings.ToLower(strings.TrimSpace(in.Format))
	folder := strings.TrimSpace(in.Folder)
	if folder == "" {
		var suffix [8]byte
		if _, err := rand.Read(suffix[:]); err != nil {
			return nil, ExportOut{}, fmt.Errorf("generate export folder: %w", err)
		}
		folder = "export-" + time.Now().UTC().Format("20060102t150405z") + "-" + hex.EncodeToString(suffix[:])
	}
	res, err := a.store.Export(run, format, folder, a.Root())
	if err != nil {
		return nil, ExportOut{}, err
	}
	return nil, ExportOut{Result: *res, ScopeFiltered: true}, nil
}
