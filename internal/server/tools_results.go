package server

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// ---- get_results ----

type StartRunIn struct {
	ScopeRoot string `json:"scope_root,omitempty" jsonschema:"registrable domain to enumerate (for example \"bmkg.go.id\"); required on the first call — this process then pins to that root and later calls must use the same root"`
	Fixture   bool   `json:"fixture,omitempty" jsonschema:"explicitly request in-process, clearly labeled fixture/test mode (no real backends, no network); for tests and local development only"`
}
type StartRunOut struct {
	RunID string `json:"run_id"`
	Root  string `json:"root"`
}

func (a *App) handleStartRun(ctx context.Context, req *mcp.CallToolRequest, in StartRunIn) (*mcp.CallToolResult, StartRunOut, error) {
	if err := a.pinScope(in.ScopeRoot, in.Fixture || a.cfg.Fixture); err != nil {
		return nil, StartRunOut{}, err
	}
	run, err := a.store.CreateRun(a.fixtureMode())
	if err != nil {
		return nil, StartRunOut{}, err
	}
	return nil, StartRunOut{RunID: run.ID, Root: a.Root()}, nil
}

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
	if err := a.ensurePinned(); err != nil {
		return nil, ResultsOut{}, err
	}
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
	ScopeRoot string              `json:"scope_root"`
	DataDir   string              `json:"data_dir"`
	Fixture   bool                `json:"fixture"`
	Pinned    bool                `json:"pinned"`
	Settings  OperationalSettings `json:"settings" jsonschema:"effective server-owned operational parameters used by the real backends"`
	Backends  []backend.Info      `json:"backends"`
}

// OperationalSettings documents the effective server-owned execution
// parameters so results can be interpreted and reproduced by hand.
type OperationalSettings struct {
	SubfinderRateLimit int      `json:"subfinder_rate_limit" jsonschema:"subfinder requests per second (-rl)"`
	DnsxRateLimit      int      `json:"dnsx_rate_limit" jsonschema:"dnsx queries per second (-rl)"`
	DnsxThreads        int      `json:"dnsx_threads" jsonschema:"dnsx worker threads (-t)"`
	DnsxRetry          int      `json:"dnsx_retry" jsonschema:"dnsx retries per query (-retry)"`
	DnsxQueryTimeout   string   `json:"dnsx_query_timeout" jsonschema:"dnsx per-query timeout"`
	AlterXOutputLimit  string   `json:"alterx_output_limit" jsonschema:"alterx output size limit"`
	Resolvers          []string `json:"resolvers,omitempty" jsonschema:"configured dnsx resolvers; empty means dnsx built-in resolvers"`
	RecordTypes        []string `json:"record_types" jsonschema:"DNS record types queried for every resolution"`
}

func (a *App) operationalSettings() OperationalSettings {
	resolvers := []string{}
	for _, r := range strings.Split(a.cfg.Backend.DnsxResolvers, ",") {
		trimmed := strings.TrimSpace(r)
		if trimmed != "" {
			resolvers = append(resolvers, trimmed)
		}
	}
	return OperationalSettings{
		SubfinderRateLimit: adapters.DefaultSubfinderRate,
		DnsxRateLimit:      adapters.DNSXRateLimit,
		DnsxThreads:        adapters.DNSXThreads,
		DnsxRetry:          adapters.DNSXRetry,
		DnsxQueryTimeout:   adapters.DNSXQueryTimeout,
		AlterXOutputLimit:  adapters.AlterXOutputLimit,
		Resolvers:          resolvers,
		RecordTypes:        []string{"A", "AAAA", "CNAME"},
	}
}

func (a *App) handleListBackends(ctx context.Context, req *mcp.CallToolRequest, in BackendsIn) (*mcp.CallToolResult, BackendsOut, error) {
	_, pinned := a.pinnedRoot()
	return nil, BackendsOut{
		ScopeRoot: a.Root(),
		DataDir:   a.DataDir(),
		Fixture:   a.fixtureMode(),
		Pinned:    pinned,
		Settings:  a.operationalSettings(),
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
