package server

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// ---- discover_subdomains ----

type DiscoverIn struct {
	RunID          string `json:"run_id,omitempty" jsonschema:"run to append to; empty uses the latest run, or starts one when none exists"`
	MaxRecords     *int   `json:"max_records,omitempty" jsonschema:"optional positive cap on records per call, 1–5000"`
	TimeoutSeconds *int   `json:"timeout_seconds,omitempty" jsonschema:"0 or omitted uses the 120-second default; otherwise 1–300 seconds"`
}

type DiscoverOut struct {
	RunID   string          `json:"run_id"`
	Root    string          `json:"root"`
	Mode    string          `json:"mode"`
	Fixture bool            `json:"fixture"`
	Count   int             `json:"count"`
	Records []*model.Record `json:"records"`
	Backend backend.Info    `json:"backend"`
}

func (a *App) handleDiscover(ctx context.Context, req *mcp.CallToolRequest, in DiscoverIn) (*mcp.CallToolResult, DiscoverOut, error) {
	if err := a.validateRunForWrite(in.RunID); err != nil {
		return nil, DiscoverOut{}, err
	}
	maxRecords, err := clampCap(in.MaxRecords, CapMaxRecordsPerCall, CapMaxRecordsPerCall, "max_records")
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	timeout, err := timeoutForTool(in.TimeoutSeconds)
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	if a.cfg.External.Requested {
		if err := a.requireExternal(true); err != nil {
			return nil, DiscoverOut{}, err
		}
	}
	run, err := a.runForWrite(in.RunID)
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	mode, fixture := fixtureMode, true
	backendInfo := a.fixtureBackendInfo("mock.subfinder", backend.KindPassive)
	var records []*model.Record
	if a.cfg.External.Requested {
		records, err = a.external.Discover(ctx, backend.DiscoverRequest{RunID: run.ID, Root: a.Root(), MaxRecords: maxRecords, Timeout: timeout})
		mode, fixture = externalMode, false
		backendInfo = a.externalBackendInfo("subfinder", backend.KindPassive)
	} else {
		records, err = a.disc.Discover(ctx, backend.DiscoverRequest{RunID: run.ID, Root: a.Root(), MaxRecords: maxRecords, Timeout: timeout})
	}
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	stored, err := a.upsertAll(run, records)
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	return nil, DiscoverOut{
		RunID:   run.ID,
		Root:    a.Root(),
		Mode:    mode,
		Fixture: fixture,
		Count:   len(stored),
		Records: sampleRecords(stored),
		Backend: backendInfo,
	}, nil
}

// ---- generate_candidates ----

type GenerateIn struct {
	RunID          string `json:"run_id,omitempty" jsonschema:"run to append to; empty uses the latest run"`
	MaxCandidates  *int   `json:"max_candidates,omitempty" jsonschema:"optional positive cap on generated candidates, 1–5000"`
	TimeoutSeconds *int   `json:"timeout_seconds,omitempty" jsonschema:"0 or omitted uses the 120-second default; otherwise 1–300 seconds"`
}

type GenerateOut struct {
	RunID     string          `json:"run_id"`
	Root      string          `json:"root"`
	Mode      string          `json:"mode"`
	Fixture   bool            `json:"fixture"`
	Seeds     int             `json:"seeds"`
	Generated int             `json:"generated"`
	Records   []*model.Record `json:"records"`
	Backend   backend.Info    `json:"backend"`
}

func (a *App) handleGenerateCandidates(ctx context.Context, req *mcp.CallToolRequest, in GenerateIn) (*mcp.CallToolResult, GenerateOut, error) {
	if err := a.validateRunForWrite(in.RunID); err != nil {
		return nil, GenerateOut{}, err
	}
	maxOut, err := clampCap(in.MaxCandidates, CapMaxCandidates, CapMaxCandidates, "max_candidates")
	if err != nil {
		return nil, GenerateOut{}, err
	}
	timeout, err := timeoutForTool(in.TimeoutSeconds)
	if err != nil {
		return nil, GenerateOut{}, err
	}
	run, err := a.runForRead(in.RunID)
	if err != nil {
		return nil, GenerateOut{}, err
	}
	seeds := hostnames(run.InScope(""))
	if len(seeds) == 0 {
		return nil, GenerateOut{}, fmt.Errorf("run %s has no in-scope hosts to seed permutations; call discover_subdomains or resolve_hosts first", run.ID)
	}
	if len(seeds) > CapMaxSeedHosts {
		return nil, GenerateOut{}, fmt.Errorf("run %s has %d seed hosts; the server hard cap is %d", run.ID, len(seeds), CapMaxSeedHosts)
	}
	mode, fixture := fixtureMode, true
	backendInfo := a.fixtureBackendInfo("mock.alterx", backend.KindCandidates)
	var records []*model.Record
	if a.cfg.External.Requested {
		if err := a.requireExternal(false); err != nil {
			return nil, GenerateOut{}, err
		}
		records, err = a.external.Generate(ctx, backend.CandidateRequest{RunID: run.ID, Root: a.Root(), Seeds: seeds, MaxOut: maxOut, Timeout: timeout})
		mode, fixture = externalMode, false
		backendInfo = a.externalBackendInfo("alterx", backend.KindCandidates)
	} else {
		records, err = a.gen.Generate(ctx, backend.CandidateRequest{RunID: run.ID, Root: a.Root(), Seeds: seeds, MaxOut: maxOut, Timeout: timeout})
	}
	if err != nil {
		return nil, GenerateOut{}, err
	}
	stored, err := a.upsertAll(run, records)
	if err != nil {
		return nil, GenerateOut{}, err
	}
	return nil, GenerateOut{
		RunID:     run.ID,
		Root:      a.Root(),
		Mode:      mode,
		Fixture:   fixture,
		Seeds:     len(seeds),
		Generated: len(stored),
		Records:   sampleRecords(stored),
		Backend:   backendInfo,
	}, nil
}

func hostnames(records []*model.Record) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Host)
	}
	return out
}
