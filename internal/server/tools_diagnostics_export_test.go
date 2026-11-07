package server

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorNoFailuresInDefaultMode(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "doctor", nil)
	var out DoctorOut
	mustJSON(t, raw, &out)
	if !out.OK {
		t.Fatalf("doctor reported failures: %+v", out.Checks)
	}
	sawPolicy := false
	for _, c := range out.Checks {
		if c.Name == "scope_policy" && c.State == CheckOK {
			sawPolicy = true
		}
	}
	if !sawPolicy {
		t.Fatalf("scope policy check missing: %+v", out.Checks)
	}
}

func TestDoctorPreservesExistingProbePath(t *testing.T) {
	app, err := NewApp(testConfig(t, nil), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(app.DataDir(), ".doctor-write-probe")
	want := []byte("keep this user file")
	if err := os.WriteFile(probe, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := app.Doctor(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(probe)
	if err != nil {
		t.Fatalf("doctor removed an existing probe-named file: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("doctor overwrote existing probe-named file: got %q, want %q", got, want)
	}
}

func TestDoctorDoesNotFollowProbeSymlink(t *testing.T) {
	app, err := NewApp(testConfig(t, nil), testLogger())
	if err != nil {
		t.Fatal(err)
	}
	probe := filepath.Join(app.DataDir(), ".doctor-write-probe")
	target := filepath.Join(t.TempDir(), "outside-sentinel")
	want := []byte("outside data")
	if err := os.WriteFile(target, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, probe); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := app.Doctor(); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(target)
	if err != nil || string(got) != string(want) {
		t.Fatalf("doctor changed symlink target: got %q, err=%v", got, err)
	}
	if fi, err := os.Lstat(probe); err != nil || fi.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("doctor removed or replaced probe symlink: info=%v err=%v", fi, err)
	}
}

func TestDoctorFailsWhenRequestedExternalModeIsUnauthorized(t *testing.T) {
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.External.Requested = true
	})
	session, _ := connectInProcess(t, cfg)
	raw := callTool(t, session, "doctor", nil)
	var out DoctorOut
	mustJSON(t, raw, &out)
	if out.OK {
		t.Fatalf("doctor reported OK although requested external mode lacks authorization: %+v", out.Checks)
	}
	for _, check := range out.Checks {
		if check.Name == "external_gate" {
			if check.State != CheckFail || !strings.Contains(check.Detail, "authorization") {
				t.Fatalf("external gate check = %+v, want fail with authorization reason", check)
			}
			return
		}
	}
	t.Fatalf("external gate check missing: %+v", out.Checks)
}

func TestExportValidation(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	callTool(t, session, "discover_subdomains", nil)
	msg := callToolErr(t, session, "export_results", map[string]any{"format": "xml"})
	if !strings.Contains(msg, "jsonl") || !strings.Contains(msg, "csv") {
		t.Fatalf("format error not actionable: %q", msg)
	}
	msg = callToolErr(t, session, "export_results", map[string]any{"format": "jsonl", "folder": "../escape"})
	if !strings.Contains(msg, "folder") {
		t.Fatalf("folder validation error = %q", msg)
	}
}
