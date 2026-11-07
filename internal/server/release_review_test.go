package server

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func TestDiscoveryReportsCapWithoutClaimingTruncation(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	var out DiscoverOut
	mustJSON(t, callTool(t, session, "discover_subdomains", map[string]any{"max_records": 1}), &out)
	if out.Count != 1 || !out.CapReached || out.MaxRecords != 1 || out.TimeoutSeconds != 120 || !strings.Contains(out.Warning, "may be truncated") {
		t.Fatalf("unexpected discovery cap report: %+v", out)
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
