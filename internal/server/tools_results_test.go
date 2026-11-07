package server

import (
	"context"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func TestResponseSampleIsBounded(t *testing.T) {
	records := make([]*model.Record, 25)
	if got := len(sampleRecords(records)); got != 20 {
		t.Fatalf("sample has %d records", got)
	}
	if got := len(sampleRecords(records[:3])); got != 3 {
		t.Fatalf("small sample has %d records", got)
	}
}

func TestStartRunCreatesDistinctRuns(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	var first, second StartRunOut
	mustJSON(t, callTool(t, session, "start_run", nil), &first)
	mustJSON(t, callTool(t, session, "start_run", nil), &second)
	if first.RunID == "" || second.RunID == "" || first.RunID == second.RunID {
		t.Fatalf("runs: %+v %+v", first, second)
	}
}

func TestPaginationBounds(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "discover_subdomains", nil)
	var disc discoverOut
	mustJSON(t, raw, &disc)

	if msg := callToolErr(t, session, "get_results", map[string]any{"page": intPtr(0)}); !strings.Contains(msg, "page") {
		t.Fatalf("page=0 error = %q", msg)
	}
	if msg := callToolErr(t, session, "get_results", map[string]any{"page_size": intPtr(2000)}); !strings.Contains(msg, "1000") {
		t.Fatalf("page_size cap error = %q", msg)
	}
	if msg := callToolErr(t, session, "get_results", map[string]any{"status": "nxdomain"}); !strings.Contains(msg, "status") || !strings.Contains(msg, "enum") {
		t.Fatalf("status filter error = %q", msg)
	}

	raw = callTool(t, session, "get_results", map[string]any{"run_id": disc.RunID, "page": intPtr(999), "page_size": intPtr(10)})
	var beyond ResultsOut
	mustJSON(t, raw, &beyond)
	if beyond.Total == 0 || len(beyond.Records) != 0 {
		t.Fatalf("page beyond end = %+v", beyond)
	}
}

func TestPaginationMaxIntDoesNotPanic(t *testing.T) {
	session, app := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "discover_subdomains", nil)
	var disc discoverOut
	mustJSON(t, raw, &disc)

	var out ResultsOut
	var callErr error
	var panicked any
	func() {
		defer func() { panicked = recover() }()
		_, out, callErr = app.handleGetResults(context.Background(), nil, ResultsIn{
			RunID: disc.RunID,
			Page:  intPtr(int(^uint(0) >> 1)),
		})
	}()
	if panicked != nil {
		t.Fatalf("get_results panicked for maximum page: %v", panicked)
	}
	if callErr != nil {
		t.Fatalf("get_results returned error for out-of-range page: %v", callErr)
	}
	if out.Total == 0 || len(out.Records) != 0 {
		t.Fatalf("maximum page should return an empty page with nonzero total: %+v", out)
	}
}

func TestHardCapsEnforced(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	msg := callToolErr(t, session, "discover_subdomains", map[string]any{"max_records": intPtr(9999)})
	if !strings.Contains(msg, "5000") {
		t.Fatalf("discover cap error = %q", msg)
	}
	msg = callToolErr(t, session, "resolve_hosts", map[string]any{"hosts": bigHostList(CapMaxResolveHosts + 1)})
	if !strings.Contains(msg, "2000") {
		t.Fatalf("resolve list cap error = %q", msg)
	}
	msg = callToolErr(t, session, "bruteforce_subdomains", map[string]any{"wordlist": "https://attacker/words.txt"})
	if !strings.Contains(msg, "wordlist") || !strings.Contains(msg, "enum") {
		t.Fatalf("wordlist cap error = %q", msg)
	}
}
