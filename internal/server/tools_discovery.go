package server

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// ---- discover_subdomains ----

type DiscoverIn struct {
	RunID          string `json:"run_id,omitempty" jsonschema:"run to append to; empty uses the latest run, or starts one when none exists"`
	MaxRecords     *int   `json:"max_records,omitempty" jsonschema:"positive cap on records per call, 1–5000; default 100; this is an output cap, not a network request budget"`
	TimeoutSeconds *int   `json:"timeout_seconds,omitempty" jsonschema:"0 or omitted uses the 120-second default; otherwise 1–300 seconds"`
	AllSources     bool   `json:"all_sources,omitempty" jsonschema:"request all available passive sources instead of defaults; may increase network requests and duration and does not guarantee completeness"`
}

type DiscoverOut struct {
	RunID          string          `json:"run_id"`
	Root           string          `json:"root"`
	Mode           string          `json:"mode"`
	Fixture        bool            `json:"fixture"`
	Count          int             `json:"count"`
	Records        []*model.Record `json:"records"`
	Backend        backend.Info    `json:"backend"`
	CapReached     bool            `json:"cap_reached" jsonschema:"whether returned unique names reached the requested cap; completeness remains unknown"`
	Warning        string          `json:"warning,omitempty"`
	MaxRecords     int             `json:"max_records"`
	TimeoutSeconds int             `json:"timeout_seconds"`
	AllSources     bool            `json:"all_sources" jsonschema:"whether all available passive sources were requested; fixture mode remains synthetic"`
}

func (a *App) handleDiscover(ctx context.Context, req *mcp.CallToolRequest, in DiscoverIn) (*mcp.CallToolResult, DiscoverOut, error) {
	if err := a.ensurePinned(); err != nil {
		return nil, DiscoverOut{}, err
	}
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if err := a.validateRunForWrite(in.RunID); err != nil {
		return nil, DiscoverOut{}, err
	}
	maxRecords, err := clampCap(in.MaxRecords, DefaultDiscoverRecords, CapMaxRecordsPerCall, "max_records")
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	timeout, err := timeoutForTool(in.TimeoutSeconds)
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	if !a.fixtureMode() {
		if err := a.verifyRealBackends(); err != nil {
			return nil, DiscoverOut{}, err
		}
	}
	run, err := a.runForWrite(in.RunID)
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	var records []*model.Record
	if a.fixtureMode() {
		records, err = a.disc.Discover(ctx, backend.DiscoverRequest{RunID: run.ID, Root: a.Root(), MaxRecords: maxRecords, Timeout: timeout, AllSources: in.AllSources})
	} else {
		records, err = a.external.Discover(ctx, backend.DiscoverRequest{RunID: run.ID, Root: a.Root(), MaxRecords: maxRecords, Timeout: timeout, AllSources: in.AllSources})
	}
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	stored, err := a.upsertAll(run, records)
	if err != nil {
		return nil, DiscoverOut{}, err
	}
	mode := "real"
	if a.fixtureMode() {
		mode = "fixture"
	}
	warning := "passive discovery is not guaranteed complete"
	if len(records) >= maxRecords {
		warning = "requested cap reached; results may be truncated and passive discovery is not guaranteed complete"
	}
	return nil, DiscoverOut{
		RunID:          run.ID,
		Root:           a.Root(),
		Mode:           mode,
		Fixture:        a.fixtureMode(),
		Count:          len(stored),
		Records:        sampleRecords(stored),
		Backend:        a.backendInfo("subfinder", backend.KindPassive),
		CapReached:     len(records) >= maxRecords,
		Warning:        warning,
		MaxRecords:     maxRecords,
		TimeoutSeconds: int(timeout.Seconds()),
		AllSources:     in.AllSources,
	}, nil
}

// ---- generate_candidates ----

type GenerateIn struct {
	RunID          string `json:"run_id,omitempty" jsonschema:"run to append to; empty uses the latest run"`
	MaxCandidates  *int   `json:"max_candidates,omitempty" jsonschema:"optional positive cap on generated candidates, 1–5000"`
	SeedOffset     *int   `json:"seed_offset,omitempty" jsonschema:"0-based offset over stored in-scope seed hosts; minimum 0"`
	SeedSnapshot   string `json:"seed_snapshot,omitempty" jsonschema:"snapshot token returned by a previous generation call; required when seed_offset is nonzero"`
	SeedLimit      *int   `json:"seed_limit,omitempty" jsonschema:"seed batch size over stored in-scope hosts, 1–2000; defaults to 2000"`
	TimeoutSeconds *int   `json:"timeout_seconds,omitempty" jsonschema:"0 or omitted uses the 120-second default; otherwise 1–300 seconds"`
	Enrich         bool   `json:"enrich,omitempty" jsonschema:"enrich permutations using words from in-scope seeds; may increase candidate volume, still capped by max_candidates"`
}

type GenerateOut struct {
	RunID          string          `json:"run_id"`
	Root           string          `json:"root"`
	Mode           string          `json:"mode"`
	Fixture        bool            `json:"fixture"`
	Seeds          int             `json:"seeds"`
	Generated      int             `json:"generated"`
	Records        []*model.Record `json:"records"`
	Backend        backend.Info    `json:"backend"`
	SeedTotal      int             `json:"seed_total,omitempty"`
	SeedOffset     int             `json:"seed_offset,omitempty"`
	SeedNextOffset *int            `json:"seed_next_offset,omitempty"`
	SeedSnapshot   string          `json:"seed_snapshot,omitempty" jsonschema:"process-local snapshot token; reuse with seed_next_offset to avoid shifted seeds"`
	TimeoutSeconds int             `json:"timeout_seconds" jsonschema:"timeout applied to the generation call"`
	Enrich         bool            `json:"enrich" jsonschema:"whether seed-based enrichment was requested; fixture mode remains synthetic"`
}

func (a *App) handleGenerateCandidates(ctx context.Context, req *mcp.CallToolRequest, in GenerateIn) (*mcp.CallToolResult, GenerateOut, error) {
	if err := a.ensurePinned(); err != nil {
		return nil, GenerateOut{}, err
	}
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
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
	seedOffset := 0
	if in.SeedOffset != nil {
		if *in.SeedOffset < 0 {
			return nil, GenerateOut{}, fmt.Errorf("seed_offset must be 0 or greater; got %d", *in.SeedOffset)
		}
		seedOffset = *in.SeedOffset
	}
	seedLimit := CapMaxSeedHosts
	if in.SeedLimit != nil {
		if *in.SeedLimit <= 0 || *in.SeedLimit > CapMaxSeedHosts {
			return nil, GenerateOut{}, fmt.Errorf("seed_limit must be between 1 and %d; got %d", CapMaxSeedHosts, *in.SeedLimit)
		}
		seedLimit = *in.SeedLimit
	}
	var allSeeds []string
	snapshotID := in.SeedSnapshot
	if snapshotID != "" {
		snapshot, ok := a.seedSnapshots[snapshotID]
		if !ok || snapshot.runID != run.ID {
			return nil, GenerateOut{}, fmt.Errorf("seed snapshot is unavailable for this run; restart generation at seed_offset 0")
		}
		allSeeds = snapshot.hosts
	} else {
		if seedOffset != 0 {
			return nil, GenerateOut{}, fmt.Errorf("seed_snapshot is required for nonzero seed_offset; restart generation at offset 0")
		}
		allSeeds = hostnames(run.InScope(""))
	}
	if len(allSeeds) == 0 {
		return nil, GenerateOut{}, fmt.Errorf("run %s has no in-scope hosts to seed permutations; call discover_subdomains or resolve_hosts first", run.ID)
	}
	if seedOffset > len(allSeeds) {
		seedOffset = len(allSeeds)
	}
	end := seedOffset + seedLimit
	if end > len(allSeeds) {
		end = len(allSeeds)
	}
	seeds := allSeeds[seedOffset:end]
	mode := "real"
	if a.fixtureMode() {
		mode = "fixture"
	}
	if len(seeds) == 0 {
		return nil, GenerateOut{RunID: run.ID, Root: a.Root(), Mode: mode, Fixture: a.fixtureMode(), SeedTotal: len(allSeeds), SeedOffset: seedOffset, Records: []*model.Record{}, Backend: a.backendInfo("alterx", backend.KindCandidates), Enrich: in.Enrich}, nil
	}
	if !a.fixtureMode() {
		if err := a.verifyRealBackends(); err != nil {
			return nil, GenerateOut{}, err
		}
	}
	var records []*model.Record
	if a.fixtureMode() {
		records, err = a.gen.Generate(ctx, backend.CandidateRequest{RunID: run.ID, Root: a.Root(), Seeds: seeds, MaxOut: maxOut, Timeout: timeout, Enrich: in.Enrich})
	} else {
		records, err = a.external.Generate(ctx, backend.CandidateRequest{RunID: run.ID, Root: a.Root(), Seeds: seeds, MaxOut: maxOut, Timeout: timeout, Enrich: in.Enrich})
	}
	if err != nil {
		return nil, GenerateOut{}, err
	}
	stored, err := a.upsertAll(run, records)
	if err != nil {
		return nil, GenerateOut{}, err
	}
	var next *int
	if end < len(allSeeds) {
		n := end
		next = &n
		if snapshotID == "" {
			var random [16]byte
			if _, err := rand.Read(random[:]); err != nil {
				return nil, GenerateOut{}, fmt.Errorf("create seed snapshot: %w", err)
			}
			snapshotID = hex.EncodeToString(random[:])
			if a.seedSnapshots == nil {
				a.seedSnapshots = make(map[string]seedSnapshot)
			}
			if len(a.seedSnapshotOrder) >= 8 {
				delete(a.seedSnapshots, a.seedSnapshotOrder[0])
				a.seedSnapshotOrder = a.seedSnapshotOrder[1:]
			}
			a.seedSnapshots[snapshotID] = seedSnapshot{runID: run.ID, hosts: allSeeds}
			a.seedSnapshotOrder = append(a.seedSnapshotOrder, snapshotID)
		}
	}
	return nil, GenerateOut{
		RunID:          run.ID,
		Root:           a.Root(),
		Mode:           mode,
		Fixture:        a.fixtureMode(),
		Seeds:          len(seeds),
		Generated:      len(stored),
		Records:        sampleRecords(stored),
		Backend:        a.backendInfo("alterx", backend.KindCandidates),
		SeedTotal:      len(allSeeds),
		SeedOffset:     seedOffset,
		SeedNextOffset: next,
		SeedSnapshot:   snapshotID,
		TimeoutSeconds: effectiveTimeoutSeconds(timeout),
		Enrich:         in.Enrich,
	}, nil
}

func hostnames(records []*model.Record) []string {
	out := make([]string, 0, len(records))
	for _, r := range records {
		out = append(out, r.Host)
	}
	return out
}
