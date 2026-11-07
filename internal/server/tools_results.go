package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// ---- get_results ----

type ResultsIn struct {
	RunID    string `json:"run_id,omitempty" jsonschema:"run to read; empty uses the latest run"`
	Status   string `json:"status,omitempty" jsonschema:"optional filter: candidate, resolved, no_answer, timeout or dns_error; empty means all statuses"`
	Page     *int   `json:"page,omitempty" jsonschema:"1-based page number, minimum 1; default 1"`
	PageSize *int   `json:"page_size,omitempty" jsonschema:"page size 1–1000; default 100"`
}

type ResultsOut struct {
	RunID        string          `json:"run_id"`
	Root         string          `json:"root"`
	Total        int             `json:"total"`
	Page         int             `json:"page"`
	PageSize     int             `json:"page_size"`
	TotalPages   int             `json:"total_pages"`
	StatusCounts map[string]int  `json:"status_counts"`
	DroppedCount int             `json:"dropped_count"`
	Records      []*model.Record `json:"records"`
}

func (a *App) handleGetResults(ctx context.Context, req *mcp.CallToolRequest, in ResultsIn) (*mcp.CallToolResult, ResultsOut, error) {
	run, err := a.runForRead(in.RunID)
	if err != nil {
		return nil, ResultsOut{}, err
	}
	statusFilter := model.Status("")
	if strings.TrimSpace(in.Status) != "" {
		statusFilter = model.Status(strings.ToLower(strings.TrimSpace(in.Status)))
		if !statusFilter.Valid() {
			return nil, ResultsOut{}, fmt.Errorf("unknown status %q; valid filters: candidate, resolved, no_answer, timeout, dns_error", in.Status)
		}
	}
	page := 1
	if in.Page != nil {
		if *in.Page < 1 {
			return nil, ResultsOut{}, fmt.Errorf("page must be 1 or greater; got %d", *in.Page)
		}
		page = *in.Page
	}
	pageSize := CapDefaultPageSize
	if in.PageSize != nil {
		if *in.PageSize < 1 || *in.PageSize > CapMaxPageSize {
			return nil, ResultsOut{}, fmt.Errorf("page_size must be between 1 and %d; got %d", CapMaxPageSize, *in.PageSize)
		}
		pageSize = *in.PageSize
	}

	all := run.InScope(statusFilter)
	total := len(all)
	totalPages := (total + pageSize - 1) / pageSize
	if totalPages == 0 {
		totalPages = 1
	}
	records := []*model.Record{}
	if page <= totalPages {
		start := (page - 1) * pageSize
		if start < total {
			end := start + pageSize
			if end > total {
				end = total
			}
			records = all[start:end]
		}
	}
	return nil, ResultsOut{
		RunID:        run.ID,
		Root:         a.Root(),
		Total:        total,
		Page:         page,
		PageSize:     pageSize,
		TotalPages:   totalPages,
		StatusCounts: statusCounts(all),
		DroppedCount: len(run.Dropped()),
		Records:      records,
	}, nil
}

// ---- list_backends ----

type BackendsIn struct{}

type BackendsOut struct {
	ScopeRoot string         `json:"scope_root"`
	DataDir   string         `json:"data_dir"`
	External  ExternalGate   `json:"external"`
	Backends  []backend.Info `json:"backends"`
}

func (a *App) handleListBackends(ctx context.Context, req *mcp.CallToolRequest, in BackendsIn) (*mcp.CallToolResult, BackendsOut, error) {
	return nil, BackendsOut{
		ScopeRoot: a.Root(),
		DataDir:   a.DataDir(),
		External:  a.externalGate(),
		Backends:  a.BackendInfos(),
	}, nil
}

// ---- doctor ----

type DoctorIn struct{}

type DoctorOut struct {
	OK     bool          `json:"ok"`
	Checks []DoctorCheck `json:"checks"`
}

func (a *App) handleDoctor(ctx context.Context, req *mcp.CallToolRequest, in DoctorIn) (*mcp.CallToolResult, DoctorOut, error) {
	checks, err := a.Doctor()
	if err != nil {
		return nil, DoctorOut{}, err
	}
	ok := true
	for _, c := range checks {
		if c.State == CheckFail {
			ok = false
		}
	}
	return nil, DoctorOut{OK: ok, Checks: checks}, nil
}
