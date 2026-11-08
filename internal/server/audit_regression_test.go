package server

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/google/jsonschema-go/jsonschema"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func auditToolSchema(t *testing.T, raw any) *jsonschema.Schema {
	t.Helper()
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("marshal MCP schema (%T): %v", raw, err)
	}
	var schema jsonschema.Schema
	if err := json.Unmarshal(encoded, &schema); err != nil {
		t.Fatalf("decode MCP schema into JSON Schema: %v", err)
	}
	return &schema
}

func TestResolveAllRejectedInputsDoNotCreateRunSlot(t *testing.T) {
	session, app := connectInProcess(t, testConfig(t, nil))
	callToolErr(t, session, "resolve_hosts", map[string]any{
		"hosts": []string{"example.com", "attacker.test"},
	})
	if got := len(app.Store().Runs()); got != 0 {
		t.Fatalf("all-rejected resolve created %d run slots", got)
	}
}

func TestResolveAllRejectedInputsReuseExistingRun(t *testing.T) {
	session, app := connectInProcess(t, testConfig(t, nil))
	var discovered discoverOut
	mustJSON(t, callTool(t, session, "discover_subdomains", nil), &discovered)

	var resolved ResolveOut
	mustJSON(t, callTool(t, session, "resolve_hosts", map[string]any{
		"run_id": discovered.RunID,
		"hosts":  []string{"example.com", "attacker.test"},
	}), &resolved)
	if resolved.RunID != discovered.RunID || resolved.Accepted != 0 || len(resolved.Dropped) != 2 {
		t.Fatalf("all-rejected result = %+v", resolved)
	}
	runs := app.Store().Runs()
	droppedCount := 0
	if len(runs) > 0 {
		droppedCount = len(runs[0].Dropped())
	}
	if len(runs) != 1 || runs[0].ID != discovered.RunID || droppedCount != 2 {
		t.Fatalf("all-rejected intake did not reuse/persist to existing run: runs=%d dropped=%d", len(runs), droppedCount)
	}
}

func TestDoctorProbeUsesOpenedStoreRootAfterPathReplacement(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows prevents renaming an opened data directory")
	}
	base := t.TempDir()
	dataDir := filepath.Join(base, "data")
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.DataDir = dataDir
	})
	app, err := NewApp(cfg, testLogger())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = app.Store().Close() })

	moved := filepath.Join(base, "opened-data")
	if err := os.Rename(dataDir, moved); err != nil {
		t.Fatal(err)
	}
	redirectedFile := filepath.Join(base, "not-a-directory")
	if err := os.WriteFile(redirectedFile, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(redirectedFile, dataDir); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	checks, err := app.Doctor()
	if err != nil {
		t.Fatal(err)
	}
	for _, check := range checks {
		if check.Name == "data_dir" {
			if check.State != CheckOK {
				t.Fatalf("doctor followed replacement of configured data-dir path: %+v", check)
			}
			data, readErr := os.ReadFile(redirectedFile)
			if readErr != nil || string(data) != "preserve" {
				t.Fatalf("doctor modified redirected target: %q err=%v", data, readErr)
			}
			return
		}
	}
	t.Fatalf("data_dir check missing: %+v", checks)
}

func TestToolSchemasReflectHandlerBoundsAndEnums(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	listed, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	tools := make(map[string]*mcp.Tool, len(listed.Tools))
	for _, tool := range listed.Tools {
		tools[tool.Name] = tool
	}
	assertBounds := func(toolName, property string, wantMin, wantMax float64) {
		t.Helper()
		tool := tools[toolName]
		if tool == nil || tool.InputSchema == nil {
			t.Fatalf("tool/schema %q missing", toolName)
		}
		p := auditToolSchema(t, tool.InputSchema).Properties[property]
		if p == nil || p.Minimum == nil || p.Maximum == nil || *p.Minimum != wantMin || *p.Maximum != wantMax {
			t.Errorf("%s.%s schema bounds = %+v, want [%v,%v]", toolName, property, p, wantMin, wantMax)
		}
	}
	assertEnum := func(toolName, property string, want []any) {
		t.Helper()
		tool := tools[toolName]
		if tool == nil || tool.InputSchema == nil {
			t.Fatalf("tool/schema %q missing", toolName)
		}
		p := auditToolSchema(t, tool.InputSchema).Properties[property]
		if p == nil || !reflect.DeepEqual(p.Enum, want) {
			t.Errorf("%s.%s schema enum = %v, want %v", toolName, property, p, want)
		}
	}

	assertBounds("discover_subdomains", "max_records", 1, 5000)
	assertBounds("discover_subdomains", "timeout_seconds", 0, 300)
	assertBounds("generate_candidates", "max_candidates", 1, 5000)
	assertBounds("bruteforce_subdomains", "max_words", 1, 1000)
	assertBounds("resolve_hosts", "max_hosts", 1, 2000)
	hosts := auditToolSchema(t, tools["resolve_hosts"].InputSchema).Properties["hosts"]
	if hosts == nil || hosts.MaxItems == nil || *hosts.MaxItems != CapMaxResolveHosts {
		t.Errorf("resolve_hosts.hosts schema maxItems = %+v, want %d", hosts, CapMaxResolveHosts)
	}
	page := auditToolSchema(t, tools["get_results"].InputSchema).Properties["page"]
	if page == nil || page.Minimum == nil || *page.Minimum != 1 || page.Maximum != nil {
		t.Errorf("get_results.page schema = %+v, want minimum 1 and no maximum", page)
	}
	assertBounds("get_results", "page_size", 1, 1000)
	assertEnum("bruteforce_subdomains", "wordlist", []any{"", "preset-small"})
	assertEnum("get_results", "status", []any{"", "candidate", "resolved", "no_answer", "timeout", "dns_error"})
	assertEnum("export_results", "format", []any{"jsonl", "csv"})
	if pattern := auditToolSchema(t, tools["get_results"].InputSchema).Properties["run_id"].Pattern; pattern == "" {
		t.Error("get_results.run_id schema has no store-compatible pattern")
	}
	if pattern := auditToolSchema(t, tools["export_results"].InputSchema).Properties["folder"].Pattern; pattern == "" {
		t.Error("export_results.folder schema has no SafeName-compatible pattern")
	}

	for _, field := range []string{"words_queried", "records", "wildcard_check"} {
		p := auditToolSchema(t, tools["bruteforce_subdomains"].OutputSchema).Properties[field]
		if p == nil || strings.TrimSpace(p.Description) == "" {
			t.Errorf("bruteforce_subdomains output field %q lacks a description", field)
		}
	}
	for _, field := range []string{"accepted", "dropped", "status_counts"} {
		p := auditToolSchema(t, tools["resolve_hosts"].OutputSchema).Properties[field]
		if p == nil || strings.TrimSpace(p.Description) == "" {
			t.Errorf("resolve_hosts output field %q lacks a description", field)
		}
	}
}

func TestRealBruteforceUsesManagedTemporaryWordlist(t *testing.T) {
	dir := t.TempDir()
	bins := map[string]string{}
	for _, name := range []string{"subfinder", "dnsx", "alterx"} {
		bins[name] = filepath.Join(dir, name)
	}
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.Fixture = false
		c.Backend.SubfinderBin = bins["subfinder"]
		c.Backend.DnsxBin = bins["dnsx"]
		c.Backend.AlterxBin = bins["alterx"]
	})
	session, app := connectInProcess(t, cfg)
	app.verifyPinnedBinary = func(name, path string) (adapters.PinnedTool, string, error) {
		return adapters.PinnedTool{Name: name, Version: "test-pin", License: "MIT", Platform: "linux/amd64"}, "test-digest", nil
	}

	var wordlistPath string
	fake := &adapters.FakeRunner{Fn: func(spec adapters.ExecSpec) ([]byte, []byte, error) {
		for i, arg := range spec.Args {
			if arg == "-w" && i+1 < len(spec.Args) {
				wordlistPath = spec.Args[i+1]
				break
			}
		}
		if wordlistPath == "" {
			return nil, nil, fmt.Errorf("dnsx wordlist argument missing")
		}
		managedDir := filepath.Join(app.DataDir(), "work")
		rel, err := filepath.Rel(managedDir, wordlistPath)
		if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
			return nil, nil, fmt.Errorf("wordlist path %q is outside managed work directory", wordlistPath)
		}
		data, err := os.ReadFile(wordlistPath)
		if err != nil {
			return nil, nil, err
		}
		words := presetWords("preset-small")
		if len(words) > 2 {
			words = words[:2]
		}
		want := strings.Join(words, "\n") + "\n"
		if string(data) != want {
			return nil, nil, fmt.Errorf("managed wordlist contents = %q, want %q", data, want)
		}
		return []byte("{\"host\":\"api.corp.customer-example.net\",\"a\":[\"192.0.2.1\"]}\n"), nil, nil
	}}
	ext, err := adapters.NewExternalBackends(app.scope, app.builder, fake)
	if err != nil {
		t.Fatal(err)
	}
	app.external = ext

	var out BruteforceOut
	mustJSON(t, callTool(t, session, "bruteforce_subdomains", map[string]any{"max_words": 2}), &out)
	if out.WordsQueried != 2 || out.WildcardCheck != "no_canary_answer" {
		t.Fatalf("bruteforce output = %+v", out)
	}
	if wordlistPath == "" {
		t.Fatal("fake backend did not observe a managed wordlist path")
	}
	if _, err := os.Stat(wordlistPath); !os.IsNotExist(err) {
		t.Fatalf("managed wordlist remains after the call: stat err=%v", err)
	}
	entries, err := os.ReadDir(filepath.Join(app.DataDir(), "work"))
	if err != nil || len(entries) != 0 {
		t.Fatalf("managed work folder not cleaned: entries=%v err=%v", entries, err)
	}
}
