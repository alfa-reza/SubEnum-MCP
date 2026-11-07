package server

import (
	"fmt"
	"strings"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/store"
)

const (
	fixtureMode         = "fixture"
	externalMode        = "external"
	responseSampleLimit = 20
)

func sampleRecords(records []*model.Record) []*model.Record {
	if len(records) > responseSampleLimit {
		return records[:responseSampleLimit]
	}
	return records
}

// ---- shared helpers ----

func (a *App) runForWrite(runID string) (*store.Run, error) {
	if strings.TrimSpace(runID) == "" {
		if run, err := a.store.LatestRun(); err == nil {
			return run, nil
		}
		return a.store.CreateRun()
	}
	if err := store.SafeRunID(runID); err != nil {
		return nil, err
	}
	return a.store.Run(runID)
}

// validateRunForWrite checks an explicit run id without creating a run. Empty
// ids are resolved only after the tool's inputs and external gate are valid.
func (a *App) validateRunForWrite(runID string) error {
	if strings.TrimSpace(runID) == "" {
		return nil
	}
	if err := store.SafeRunID(runID); err != nil {
		return err
	}
	_, err := a.store.Run(runID)
	return err
}

func (a *App) runForRead(runID string) (*store.Run, error) {
	return a.store.ResolveRun(runID)
}

func clampCap(v *int, def, max int, name string) (int, error) {
	if v == nil {
		return def, nil
	}
	if *v <= 0 {
		return 0, fmt.Errorf("%s must be a positive integer; got %d", name, *v)
	}
	if *v > max {
		return 0, fmt.Errorf("%s=%d exceeds the server hard cap of %d; split the request", name, *v, max)
	}
	return *v, nil
}

func (a *App) upsertAll(run *store.Run, records []*model.Record) ([]*model.Record, error) {
	out := make([]*model.Record, 0, len(records))
	for _, rec := range records {
		if !rec.InScope {
			return nil, fmt.Errorf("internal error: backend produced an out-of-scope record for host %q; scope filtering must happen before storage", rec.Host)
		}
		merged, err := run.Upsert(rec)
		if err != nil {
			return nil, err
		}
		out = append(out, merged)
	}
	return out, nil
}

func (a *App) fixtureBackendInfo(name, kind string) backend.Info {
	return backend.Info{Name: name, Kind: kind, State: backend.StateReadyFixture,
		Notes: "offline deterministic fixture backend; label all output as fixture data"}
}

func (a *App) externalBackendInfo(name, kind string) backend.Info {
	for _, info := range a.BackendInfos() {
		if info.Name == name && info.Kind == kind {
			return info
		}
	}
	return backend.Info{Name: name, Kind: kind, State: backend.StateUnverified, Notes: "backend state is unavailable"}
}

func timeoutForTool(seconds *int) (time.Duration, error) {
	value := 0
	if seconds != nil {
		value = *seconds
	}
	return adapters.DurationFromSeconds(value)
}

func presetWords(name string) []string {
	content := presetWordlists[name]
	words := make([]string, 0)
	for _, raw := range strings.Split(content, "\n") {
		word := strings.TrimSpace(raw)
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		words = append(words, word)
	}
	return words
}

func statusCounts(records []*model.Record) map[string]int {
	counts := map[string]int{}
	for _, r := range records {
		counts[string(r.Status)]++
	}
	return counts
}

type DroppedInput struct {
	Input  string `json:"input" jsonschema:"raw input as received"`
	Host   string `json:"host,omitempty" jsonschema:"best-effort normalized form, when one exists"`
	Reason string `json:"reason" jsonschema:"why the input was rejected at intake"`
}

// FakeRunnerForTests exposes the runner only to internal tests.
func (a *App) Runner() adapters.Runner { return a.runner }
