package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/store"
)

const responseSampleLimit = 20

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
			return a.checkRunMode(run)
		}
		return a.store.CreateRun(a.fixtureMode())
	}
	if err := store.SafeRunID(runID); err != nil {
		return nil, err
	}
	run, err := a.store.Run(runID)
	if err != nil {
		return nil, err
	}
	return a.checkRunMode(run)
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
	run, err := a.store.Run(runID)
	if err == nil {
		_, err = a.checkRunMode(run)
	}
	return err
}

func (a *App) runForRead(runID string) (*store.Run, error) {
	run, err := a.store.ResolveRun(runID)
	if err != nil {
		return nil, err
	}
	return a.checkRunMode(run)
}

// checkRunMode refuses access to a run whose persisted mode differs from this
// process. Legacy runs that predate mode persistence adopt this process's
// mode when empty; otherwise the recorded provenance decides.
func (a *App) checkRunMode(run *store.Run) (*store.Run, error) {
	if run.ModeKnown {
		if run.Fixture != a.fixtureMode() {
			return nil, fmt.Errorf("run %s was created in %s mode; this process runs in %s mode; start a new run", run.ID, modeName(run.Fixture), modeName(a.fixtureMode()))
		}
		return run, nil
	}
	// Legacy runs that already contain records cannot adopt a persisted
	// mode; their access stays provenance-checked.
	for _, record := range run.InScope("") {
		for _, provenance := range record.Provenance {
			if provenance.Fixture != a.fixtureMode() {
				return nil, fmt.Errorf("run %s contains records from a different fixture/real mode; start a new run", run.ID)
			}
		}
	}
	if len(run.InScope("")) > 0 || len(run.Dropped()) > 0 {
		return run, nil
	}
	if err := run.SetMode(a.fixtureMode()); err != nil {
		return nil, err
	}
	return run, nil
}

func modeName(fixture bool) string {
	if fixture {
		return "fixture"
	}
	return "real"
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

func (a *App) backendInfo(name, kind string) backend.Info {
	if a.fixtureMode() {
		return backend.Info{Name: "mock." + name, Kind: kind, State: backend.StateReadyFixture,
			Notes: "in-process deterministic fixture backend (test mode); output is clearly labeled as fixture data"}
	}
	for _, info := range a.BackendInfos() {
		if info.Name == name && info.Kind == kind {
			return info
		}
	}
	return backend.Info{Name: name, Kind: kind, State: backend.StateReady, Notes: "real backend"}
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

// effectiveTimeoutSeconds reports the timeout applied to an operation.
func effectiveTimeoutSeconds(timeout time.Duration) int {
	return int(timeout / time.Second)
}

// dnsOperationWarning summarizes actionable signal from the latest call:
// unobserved-host timeouts, call-limit hits even when every host answered,
// and suspected wildcard answers.
func dnsOperationWarning(records []*model.Record, counts map[string]int) string {
	var parts []string
	if n := counts[string(model.StatusTimeout)]; n > 0 {
		parts = append(parts, fmt.Sprintf("%d host(s) timed out; partial results were kept where available — retry with a smaller batch, host_offset/host_limit and/or a larger timeout_seconds", n))
	}
	for _, record := range records {
		if strings.Contains(record.Notes, model.NoteCallTimedOut) {
			parts = append(parts, "the backend call reached its time limit although every host already returned an observation; confirm with a smaller batch if needed")
			break
		}
	}
	for _, record := range records {
		if strings.Contains(record.Notes, model.NoteWildcardSuspected) {
			parts = append(parts, model.NoteWildcardSuspected)
			break
		}
	}
	return strings.Join(parts, "; ")
}

// resolveInternalChunkSize bounds one dnsx invocation inside a resolve_hosts
// call. Larger requests are processed as sequential bounded batches with
// progress notifications and persisted results after every batch.
const resolveInternalChunkSize = 500

// resolveInChunks runs the resolver over at most resolveInternalChunkSize
// hosts per backend invocation, upserting results after every batch so a later
// batch failure keeps earlier observations, and sending an MCP progress
// notification between batches.
func (a *App) resolveInChunks(ctx context.Context, req *mcp.CallToolRequest, run *store.Run, hosts []string, maxHosts int, timeout time.Duration, out *ResolveOut) error {
	total := len(hosts)
	for start, done := 0, 0; start < total; start += resolveInternalChunkSize {
		end := min(start+resolveInternalChunkSize, total)
		chunk := hosts[start:end]
		var records []*model.Record
		var err error
		if a.fixtureMode() {
			records, err = a.res.Resolve(ctx, backend.ResolveRequest{RunID: run.ID, Root: a.Root(), Hosts: chunk, MaxHosts: maxHosts, Timeout: timeout})
		} else {
			records, err = a.external.Resolve(ctx, backend.ResolveRequest{RunID: run.ID, Root: a.Root(), Hosts: chunk, MaxHosts: maxHosts, Timeout: timeout})
		}
		if err != nil {
			return err
		}
		stored, err := a.upsertAll(run, records)
		if err != nil {
			return err
		}
		done = end
		out.StatusCounts = mergeStatusCounts(out.StatusCounts, statusCounts(records))
		out.Records = sampleRecords(append(out.Records, stored...))
		if end < total {
			a.notifyProgress(ctx, req, float64(done), float64(total), fmt.Sprintf("resolved %d of %d hosts", done, total))
		}
	}
	out.TimeoutSeconds = effectiveTimeoutSeconds(timeout)
	return nil
}

// notifyProgress emits one MCP progress notification. Clients that did not
// request progress (no token) still receive the notification, which they may
// ignore.
func (a *App) notifyProgress(ctx context.Context, req *mcp.CallToolRequest, progress, total float64, message string) {
	if req == nil || req.Session == nil {
		return
	}
	params := &mcp.ProgressNotificationParams{ProgressToken: req.Params.GetProgressToken(), Progress: progress, Total: total, Message: message}
	_ = req.Session.NotifyProgress(ctx, params)
}

func mergeStatusCounts(base, add map[string]int) map[string]int {
	out := map[string]int{}
	for k, v := range base {
		out[k] += v
	}
	for k, v := range add {
		out[k] += v
	}
	return out
}

type DroppedInput struct {
	Input  string `json:"input" jsonschema:"raw input as received"`
	Host   string `json:"host,omitempty" jsonschema:"best-effort normalized form, when one exists"`
	Reason string `json:"reason" jsonschema:"why the input was rejected at intake"`
}

// FakeRunnerForTests exposes the runner only to internal tests.
func (a *App) Runner() adapters.Runner { return a.runner }
