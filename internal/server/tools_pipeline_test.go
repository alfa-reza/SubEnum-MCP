package server

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func TestToolsListed(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]bool{
		"discover_subdomains":   false,
		"generate_candidates":   false,
		"bruteforce_subdomains": false,
		"resolve_hosts":         false,
		"get_results":           false,
		"list_backends":         false,
		"doctor":                false,
		"export_results":        false,
	}
	for _, tool := range res.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
		if tool.Description == "" {
			t.Errorf("tool %q has no description", tool.Name)
		}
		if tool.InputSchema == nil {
			t.Errorf("tool %q has no input schema", tool.Name)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tool %q missing from tools/list", name)
		}
	}
}

type discoverOut struct {
	RunID   string         `json:"run_id"`
	Root    string         `json:"root"`
	Mode    string         `json:"mode"`
	Fixture bool           `json:"fixture"`
	Count   int            `json:"count"`
	Records []model.Record `json:"records"`
}

func TestFullPipelineHappyPath(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))

	// discover
	raw := callTool(t, session, "discover_subdomains", map[string]any{})
	var disc discoverOut
	mustJSON(t, raw, &disc)
	if !disc.Fixture || disc.Mode != "fixture" || disc.Count == 0 {
		t.Fatalf("discover output = %+v", disc)
	}
	if disc.Root != "example.com" {
		t.Fatalf("run root = %q", disc.Root)
	}
	for _, rec := range disc.Records {
		if rec.RunID != disc.RunID {
			t.Fatalf("record run_id %q != %q", rec.RunID, disc.RunID)
		}
		if rec.Status != model.StatusCandidate {
			t.Fatalf("discovery status = %q, want candidate", rec.Status)
		}
		if !rec.InScope {
			t.Fatal("stored discovery record out of scope")
		}
	}

	// generate candidates
	raw = callTool(t, session, "generate_candidates", map[string]any{"run_id": disc.RunID})
	var gen struct {
		Generated int `json:"generated"`
		Seeds     int `json:"seeds"`
	}
	mustJSON(t, raw, &gen)
	if gen.Seeds == 0 || gen.Generated == 0 {
		t.Fatalf("generate output = %+v", gen)
	}

	// bruteforce
	raw = callTool(t, session, "bruteforce_subdomains", map[string]any{"run_id": disc.RunID})
	var brute struct {
		WordsQueried int            `json:"words_queried"`
		StatusCounts map[string]int `json:"status_counts"`
	}
	mustJSON(t, raw, &brute)
	if brute.WordsQueried == 0 || brute.StatusCounts["resolved"] == 0 {
		t.Fatalf("bruteforce output = %+v", brute)
	}

	// resolve all stored hosts
	raw = callTool(t, session, "resolve_hosts", map[string]any{"run_id": disc.RunID})
	var resolve struct {
		Accepted     int            `json:"accepted"`
		Dropped      []DroppedInput `json:"dropped"`
		StatusCounts map[string]int `json:"status_counts"`
	}
	mustJSON(t, raw, &resolve)
	if resolve.Accepted == 0 || resolve.StatusCounts["resolved"] == 0 {
		t.Fatalf("resolve output = %+v", resolve)
	}

	// results + pagination
	raw = callTool(t, session, "get_results", map[string]any{"run_id": disc.RunID, "page_size": intPtr(10), "page": intPtr(1)})
	var page1 ResultsOut
	mustJSON(t, raw, &page1)
	if page1.Total == 0 || len(page1.Records) > 10 || page1.TotalPages < 1 {
		t.Fatalf("pagination output = %+v", page1)
	}
	for _, rec := range page1.Records {
		if !strings.HasSuffix(rec.Host, ".example.com") || rec.Host == "example.com" {
			t.Fatalf("record escaped scope boundary: %+v", rec)
		}
		if rec.Status == model.Status("nxdomain") {
			t.Fatal("record must never carry an nxdomain status")
		}
	}

	// export
	raw = callTool(t, session, "export_results", map[string]any{"run_id": disc.RunID, "format": "jsonl", "folder": "exp-happy"})
	var exp ExportOut
	mustJSON(t, raw, &exp)
	if exp.Result.Rows == 0 || exp.Result.SHA256 == "" {
		t.Fatalf("export output = %+v", exp)
	}
	if !strings.HasPrefix(exp.Result.Path, "exports/") && !strings.Contains(exp.Result.Path, "exports/") {
		t.Fatalf("export path must live in the managed exports dir: %q", exp.Result.Path)
	}
	data, err := os.ReadFile(exp.Result.PathAbs)
	if err != nil {
		t.Fatal(err)
	}
	if int(strings.Count(strings.TrimRight(string(data), "\n"), "\n"))+1 != exp.Result.Rows {
		t.Fatalf("jsonl line count does not match rows")
	}
}

func TestIntakeScopeFiltering(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "discover_subdomains", nil)
	var disc discoverOut
	mustJSON(t, raw, &disc)

	raw = callTool(t, session, "resolve_hosts", map[string]any{
		"run_id": disc.RunID,
		"hosts": []string{
			"api.example.com",
			"API.Example.COM.",
			"example.com",
			"evil.test",
			"foo..example.com",
			"büscher.example.com",
			"xn--bcher-kva.example.com",
		},
	})
	var resolve struct {
		Accepted int            `json:"accepted"`
		Dropped  []DroppedInput `json:"dropped"`
	}
	mustJSON(t, raw, &resolve)

	// accepted: "api.example.com" + its normalized duplicate; punycode is rejected.
	if resolve.Accepted != 1 {
		t.Fatalf("accepted = %d, want 1; dropped = %+v", resolve.Accepted, resolve.Dropped)
	}
	reasons := map[string]string{}
	for _, d := range resolve.Dropped {
		reasons[d.Reason] = d.Input
	}
	if _, ok := reasons["apex_excluded_root_is_out_of_scope"]; !ok {
		t.Fatalf("apex not dropped with explicit reason: %+v", resolve.Dropped)
	}
	if _, ok := reasons["out_of_scope"]; !ok {
		t.Fatalf("out-of-scope host not dropped: %+v", resolve.Dropped)
	}
	var hasMalformed, hasIDNA bool
	for _, d := range resolve.Dropped {
		if strings.HasPrefix(d.Reason, "malformed_hostname:") {
			hasMalformed = true
		}
		if d.Reason == "non_ascii_rejected_idna_policy" {
			hasIDNA = true
		}
	}
	if !hasMalformed || !hasIDNA {
		t.Fatalf("expected malformed and idna drops: %+v", resolve.Dropped)
	}

	raw = callTool(t, session, "get_results", map[string]any{"run_id": disc.RunID})
	var page ResultsOut
	mustJSON(t, raw, &page)
	if page.DroppedCount != 5 {
		t.Fatalf("dropped_count = %d, want 5", page.DroppedCount)
	}
	for _, rec := range page.Records {
		if !rec.InScope {
			t.Fatalf("rejected record leaked into pagination: %+v", rec)
		}
	}
}

func TestFixtureRecordsOnlyOnResolved(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "discover_subdomains", nil)
	var disc discoverOut
	mustJSON(t, raw, &disc)
	callTool(t, session, "bruteforce_subdomains", map[string]any{"run_id": disc.RunID})
	callTool(t, session, "resolve_hosts", map[string]any{"run_id": disc.RunID})

	raw = callTool(t, session, "get_results", map[string]any{"run_id": disc.RunID, "page_size": intPtr(CapMaxPageSize)})
	var page ResultsOut
	mustJSON(t, raw, &page)
	for _, rec := range page.Records {
		if rec.Status == model.StatusResolved && len(rec.FixtureDNSRecords) == 0 {
			t.Fatalf("resolved record without fixture DNS data: %+v", rec)
		}
		for rrtype, vals := range rec.FixtureDNSRecords {
			if rrtype != "A" && rrtype != "AAAA" && rrtype != "CNAME" {
				t.Fatalf("unexpected RR type %q", rrtype)
			}
			for _, v := range vals {
				if !strings.HasPrefix(v, "203.0.113.") && !strings.HasSuffix(v, ".example.com") {
					t.Fatalf("fixture value outside documentation ranges: %q", v)
				}
			}
		}
	}
}

func TestInvalidDNSInputsDoNotCreateRunsOrPersistDrops(t *testing.T) {
	t.Run("unknown wordlist", func(t *testing.T) {
		session, app := connectInProcess(t, testConfig(t, nil))
		callToolErr(t, session, "bruteforce_subdomains", map[string]any{"wordlist": "https://invalid.example/list"})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("invalid bruteforce request created %d runs", got)
		}
	})

	t.Run("real bruteforce missing binaries fails before creating a run", func(t *testing.T) {
		cfg := testConfig(t, func(c *Config) {
			c.ScopeRoot = "corp.customer-example.net"
			c.Fixture = false
			c.Backend.ManagedBinDir = t.TempDir()
		})
		session, app := connectInProcess(t, cfg)
		callToolErr(t, session, "bruteforce_subdomains", map[string]any{"wordlist": "preset-small"})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("failed bruteforce created %d runs", got)
		}
	})

	t.Run("empty resolve without an existing run", func(t *testing.T) {
		session, app := connectInProcess(t, testConfig(t, nil))
		callToolErr(t, session, "resolve_hosts", map[string]any{})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("empty resolve created %d runs", got)
		}
	})

	t.Run("oversized resolve input", func(t *testing.T) {
		session, app := connectInProcess(t, testConfig(t, nil))
		callToolErr(t, session, "resolve_hosts", map[string]any{"hosts": bigHostList(CapMaxResolveHosts + 1)})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("oversized resolve request created %d runs", got)
		}
	})

	t.Run("accepted count exceeds caller cap", func(t *testing.T) {
		session, app := connectInProcess(t, testConfig(t, nil))
		callToolErr(t, session, "resolve_hosts", map[string]any{
			"hosts":     []string{"api.example.com", "www.example.com", "evil.test"},
			"max_hosts": intPtr(1),
		})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("over-cap resolve request created %d runs or persisted rejected inputs", got)
		}
	})

	t.Run("real mode missing binaries fails before rejected input persistence", func(t *testing.T) {
		cfg := testConfig(t, func(c *Config) {
			c.ScopeRoot = "corp.customer-example.net"
			c.Fixture = false
			c.Backend.ManagedBinDir = t.TempDir()
		})
		session, app := connectInProcess(t, cfg)
		callToolErr(t, session, "resolve_hosts", map[string]any{
			"hosts": []string{"api.corp.customer-example.net", "evil.test"},
		})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("failed real backend check created %d runs or persisted rejected inputs", got)
		}
	})
}

func TestPipelineFailuresDoNotCreateRuns(t *testing.T) {
	t.Run("discovery cap validation", func(t *testing.T) {
		session, app := connectInProcess(t, testConfig(t, nil))
		callToolErr(t, session, "discover_subdomains", map[string]any{"max_records": 0})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("invalid discovery cap created %d runs", got)
		}
	})

	t.Run("real discovery missing binaries fails before creating a run", func(t *testing.T) {
		cfg := testConfig(t, func(c *Config) {
			c.ScopeRoot = "corp.customer-example.net"
			c.Fixture = false
			c.Backend.ManagedBinDir = t.TempDir()
		})
		session, app := connectInProcess(t, cfg)
		callToolErr(t, session, "discover_subdomains", map[string]any{})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("failed discovery created %d runs", got)
		}
	})

	t.Run("candidate generation without an existing run", func(t *testing.T) {
		session, app := connectInProcess(t, testConfig(t, nil))
		callToolErr(t, session, "generate_candidates", map[string]any{})
		if got := len(app.Store().Runs()); got != 0 {
			t.Fatalf("candidate generation without seeds created %d runs", got)
		}
	})
}

func TestResolveStoredHostsBatches(t *testing.T) {
	session, app := connectInProcess(t, testConfig(t, nil))
	run, err := app.Store().CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_, err := run.Upsert(&model.Record{RunID: run.ID, Host: fmt.Sprintf("h%d.example.com", i), Status: model.StatusCandidate, Provenance: []model.Provenance{{Backend: "mock.test", Method: model.MethodPassive, Fixture: true}}, ObservedAt: time.Now().UTC(), InScope: true})
		if err != nil {
			t.Fatal(err)
		}
	}
	raw := callTool(t, session, "resolve_hosts", map[string]any{"run_id": run.ID, "host_offset": 0, "host_limit": 2})
	var out ResolveOut
	mustJSON(t, raw, &out)
	if out.HostTotal != 5 || out.HostBatch != 2 || out.HostOffset != 0 || out.HostNextOffset == nil || *out.HostNextOffset != 2 || out.Accepted != 2 {
		t.Fatalf("batch1 = %+v", out)
	}
	raw = callTool(t, session, "resolve_hosts", map[string]any{"run_id": run.ID, "host_offset": *out.HostNextOffset, "host_limit": 2})
	mustJSON(t, raw, &out)
	if out.HostBatch != 2 || *out.HostNextOffset != 4 {
		t.Fatalf("batch2 = %+v", out)
	}
}
