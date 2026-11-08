package server

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

type recordingGenerator struct {
	backend.CandidateGenerator
	seeds [][]string
}

func TestStructuredOptionsAndWildcardFixture(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	var discovery DiscoverOut
	mustJSON(t, callTool(t, session, "discover_subdomains", map[string]any{"all_sources": true}), &discovery)
	if !discovery.AllSources || !discovery.Fixture {
		t.Fatalf("unexpected discovery: %+v", discovery)
	}
	var generated GenerateOut
	mustJSON(t, callTool(t, session, "generate_candidates", map[string]any{"run_id": discovery.RunID, "enrich": true}), &generated)
	if !generated.Enrich || !generated.Fixture {
		t.Fatalf("unexpected generation: %+v", generated)
	}
	var resolved ResolveOut
	mustJSON(t, callTool(t, session, "resolve_hosts", map[string]any{"run_id": discovery.RunID, "hosts": []string{"api." + discovery.Root}, "check_wildcard": true}), &resolved)
	if resolved.WildcardCheck != "not_checked" || !resolved.Fixture {
		t.Fatalf("fixture wildcard check: %+v", resolved)
	}
}

func (g *recordingGenerator) Generate(ctx context.Context, req backend.CandidateRequest) ([]*model.Record, error) {
	g.seeds = append(g.seeds, append([]string(nil), req.Seeds...))
	return g.CandidateGenerator.Generate(ctx, req)
}

func TestGenerationUsesStableRunBoundSeedSnapshot(t *testing.T) {
	session, app := connectInProcess(t, testConfig(t, nil))
	var discovery DiscoverOut
	mustJSON(t, callTool(t, session, "discover_subdomains", nil), &discovery)
	run, err := app.store.Run(discovery.RunID)
	if err != nil {
		t.Fatal(err)
	}
	original := hostnames(run.InScope(""))
	gen := &recordingGenerator{CandidateGenerator: app.gen}
	app.gen = gen
	var first, second GenerateOut
	mustJSON(t, callTool(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "seed_limit": 2, "max_candidates": 30}), &first)
	if first.SeedNextOffset == nil || first.SeedSnapshot == "" {
		t.Fatalf("missing snapshot: %+v", first)
	}
	_, err = run.Upsert(model.NewRecord(run.ID, "aaa."+app.Root(), model.StatusCandidate, model.Provenance{Backend: "mock.subfinder", Method: model.MethodPassive, Fixture: true}, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	mustJSON(t, callTool(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "seed_offset": *first.SeedNextOffset, "seed_limit": 2, "seed_snapshot": first.SeedSnapshot, "max_candidates": 30}), &second)
	if len(gen.seeds) != 2 || !reflect.DeepEqual(gen.seeds[0], original[:2]) || !reflect.DeepEqual(gen.seeds[1], original[2:4]) {
		t.Fatalf("snapshot pagination changed seeds: %v; original %v", gen.seeds, original)
	}
	callToolErr(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "seed_offset": 2})
	callToolErr(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "seed_offset": 2, "seed_snapshot": "missing"})
	other, err := app.store.CreateRun(true)
	if err != nil {
		t.Fatal(err)
	}
	callToolErr(t, session, "generate_candidates", map[string]any{"run_id": other.ID, "seed_offset": 2, "seed_snapshot": first.SeedSnapshot})
	for i := 0; i < 8; i++ {
		callTool(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "seed_limit": 1, "max_candidates": 1})
	}
	callToolErr(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "seed_offset": 2, "seed_snapshot": first.SeedSnapshot})
}

func TestDiscoveryReportsCapWithoutClaimingTruncation(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	var out DiscoverOut
	mustJSON(t, callTool(t, session, "discover_subdomains", map[string]any{"max_records": 1}), &out)
	if out.Count != 1 || !out.CapReached || out.MaxRecords != 1 || out.TimeoutSeconds != 120 || !strings.Contains(out.Warning, "may be truncated") {
		t.Fatalf("unexpected discovery cap report: %+v", out)
	}
}

func TestDiscoveryDefaultAndExplicitRecordCaps(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	var out DiscoverOut
	mustJSON(t, callTool(t, session, "discover_subdomains", nil), &out)
	if out.MaxRecords != DefaultDiscoverRecords {
		t.Fatalf("default max_records = %d, want %d", out.MaxRecords, DefaultDiscoverRecords)
	}
	mustJSON(t, callTool(t, session, "discover_subdomains", map[string]any{"max_records": 5000}), &out)
	if out.MaxRecords != 5000 {
		t.Fatalf("explicit max_records = %d, want 5000", out.MaxRecords)
	}
}

func TestDefaultExportFoldersAreDistinct(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	callTool(t, session, "start_run", map[string]any{})
	var first, second ExportOut
	mustJSON(t, callTool(t, session, "export_results", map[string]any{"format": "jsonl"}), &first)
	mustJSON(t, callTool(t, session, "export_results", map[string]any{"format": "csv"}), &second)
	if first.Result.Folder == second.Result.Folder || first.Result.Folder == "" || second.Result.Folder == "" {
		t.Fatalf("default export folders must be distinct: %q and %q", first.Result.Folder, second.Result.Folder)
	}
}

func TestRunModePersistedRejectsOppositeModeAndAdoptsLegacy(t *testing.T) {
	_, app := connectInProcess(t, testConfig(t, nil))
	run, err := app.store.CreateRun(!app.fixtureMode())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.runForRead(run.ID); err == nil || !strings.Contains(err.Error(), "was created in real mode") {
		t.Fatalf("expected persisted mode mismatch, got %v", err)
	}

	legacy, err := app.store.CreateRun(false)
	if err != nil {
		t.Fatal(err)
	}
	legacy.Fixture, legacy.ModeKnown = false, false
	_, err = legacy.Upsert(model.NewRecord(legacy.ID, "api."+app.Root(), model.StatusCandidate, model.Provenance{Backend: "subfinder", Method: model.MethodPassive, Fixture: false}, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.runForRead(legacy.ID); err == nil || !strings.Contains(err.Error(), "different fixture/real mode") {
		t.Fatalf("expected provenance mode mismatch, got %v", err)
	}
	legacy2, err := app.store.CreateRun(false)
	if err != nil {
		t.Fatal(err)
	}
	legacy2.Fixture, legacy2.ModeKnown = false, false
	_, err = legacy2.Upsert(model.NewRecord(legacy2.ID, "ok."+app.Root(), model.StatusCandidate, model.Provenance{Backend: "mock.subfinder", Method: model.MethodPassive, Fixture: true}, true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := app.runForRead(legacy2.ID); err != nil {
		t.Fatalf("legacy run with matching provenance should be readable without adoption: %v", err)
	}
	if legacy2.ModeKnown {
		t.Fatalf("legacy run with records must not adopt a mode")
	}

	emptyLegacy, err := app.store.CreateRun(false)
	if err != nil {
		t.Fatal(err)
	}
	emptyLegacy.Fixture, emptyLegacy.ModeKnown = false, false
	metaPath := filepath.Join(app.store.Dir(), "runs", emptyLegacy.ID, "meta.json")
	meta, err := os.ReadFile(metaPath)
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal(meta, &m); err != nil {
		t.Fatal(err)
	}
	delete(m, "fixture")
	meta, err = json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(metaPath, meta, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.runForRead(emptyLegacy.ID); err != nil {
		t.Fatalf("empty legacy run should adopt this process mode: %v", err)
	}
	if !emptyLegacy.ModeKnown || !emptyLegacy.Fixture {
		t.Fatalf("adoption did not persist mode: ModeKnown=%v Fixture=%v", emptyLegacy.ModeKnown, emptyLegacy.Fixture)
	}
	persisted, err := os.ReadFile(metaPath)
	if err != nil || !strings.Contains(string(persisted), `"fixture":true`) {
		t.Fatalf("adoption did not rewrite meta.json: %q err=%v", persisted, err)
	}
}
