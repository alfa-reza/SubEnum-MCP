package server

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultDataDirectoriesAreIsolatedByScope(t *testing.T) {
	base := t.TempDir()
	for _, root := range []string{"example.com", "example.org", "example.com"} {
		cfg := &Config{ScopeRoot: root, DataDir: base, ScopeDataDir: true, Fixture: true}
		app, err := NewApp(cfg, testLogger())
		if err != nil {
			t.Fatal(err)
		}
		if app.DataDir() != filepath.Join(base, root) {
			t.Fatalf("unexpected data directory %q", app.DataDir())
		}
		if _, err := app.Store().CreateRun(); err != nil {
			t.Fatal(err)
		}
		if err := app.Close(); err != nil {
			t.Fatal(err)
		}
	}
}

func emptyRootConfig(t *testing.T) *Config {
	return testConfig(t, func(c *Config) { c.ScopeRoot = "" })
}

func TestToolsRequirePinBeforeStartRun(t *testing.T) {
	session, _ := connectInProcess(t, emptyRootConfig(t))

	for _, tc := range []struct {
		name string
		args map[string]any
	}{
		{name: "discover_subdomains", args: map[string]any{}},
		{name: "generate_candidates", args: map[string]any{}},
		{name: "bruteforce_subdomains", args: map[string]any{}},
		{name: "resolve_hosts", args: map[string]any{}},
		{name: "get_results", args: map[string]any{}},
		{name: "export_results", args: map[string]any{"format": "jsonl"}},
	} {
		msg := callToolErr(t, session, tc.name, tc.args)
		if !strings.Contains(msg, "start_run") || !strings.Contains(msg, "scope_root") {
			t.Errorf("%s error = %q, want the start_run pin instruction", tc.name, msg)
		}
	}
}

func TestStartRunPinsAndRejectsScopeSwitch(t *testing.T) {
	session, _ := connectInProcess(t, emptyRootConfig(t))

	msg := callToolErr(t, session, "start_run", map[string]any{})
	if !strings.Contains(msg, "scope_root is required") {
		t.Fatalf("start_run without scope_root error = %q", msg)
	}

	var pinned StartRunOut
	mustJSON(t, callTool(t, session, "start_run", map[string]any{"scope_root": "example.com"}), &pinned)
	if pinned.RunID == "" || pinned.Root != "example.com" {
		t.Fatalf("pin = %+v", pinned)
	}

	// Same root again is fine and must not re-pin.
	var again StartRunOut
	mustJSON(t, callTool(t, session, "start_run", map[string]any{"scope_root": "example.com"}), &again)
	if again.Root != "example.com" {
		t.Fatalf("re-pin = %+v", again)
	}

	// Any different root must be rejected.
	if msg := callToolErr(t, session, "start_run", map[string]any{"scope_root": "other.example.com"}); !strings.Contains(msg, "pinned") {
		t.Fatalf("scope switch error = %q, want pinned refusal", msg)
	}

	// Data dir is now bound; fixture discovery works.
	_ = callTool(t, session, "discover_subdomains", map[string]any{"run_id": pinned.RunID})
}

func TestDoctorAndListBackendsBeforePin(t *testing.T) {
	session, _ := connectInProcess(t, emptyRootConfig(t))

	var listed BackendsOut
	mustJSON(t, callTool(t, session, "list_backends", nil), &listed)
	if listed.ScopeRoot != "" {
		t.Fatalf("scope_root = %q before pinning, want empty", listed.ScopeRoot)
	}
	if listed.Pinned {
		t.Fatal("server should not be pinned before start_run")
	}
	if !listed.Fixture {
		t.Fatal("test config should report fixture mode")
	}

	var doc DoctorOut
	mustJSON(t, callTool(t, session, "doctor", nil), &doc)
	var scopeCheck *DoctorCheck
	for i := range doc.Checks {
		if doc.Checks[i].Name == "scope_root" {
			scopeCheck = &doc.Checks[i]
		}
	}
	if scopeCheck == nil {
		t.Fatal("doctor is missing the scope_root check")
	}
	if scopeCheck.State != CheckWarn {
		t.Fatalf("scope_root state = %q before pinning, want %q", scopeCheck.State, CheckWarn)
	}
	if !doc.OK {
		t.Fatalf("doctor OK = false before pinning: %+v", doc.Checks)
	}
}
