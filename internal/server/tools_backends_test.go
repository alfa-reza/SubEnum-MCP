package server

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

func TestParseExternalHostsFiltersScopeAndApex(t *testing.T) {
	sc, err := scope.New("example.com", scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	got, err := parseExternalHosts([]byte("{\"host\":\"api.example.com\",\"source\":\"fixture\"}\nexample.com\nfakeexample.com\napi.example.com.attacker.test\nfoo..example.com\n"), sc)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0] != "api.example.com" {
		t.Fatalf("external parser did not fail closed on scope boundary: %v", got)
	}
}

func TestBackendsFixtureModeIsHonest(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "list_backends", nil)
	var out BackendsOut
	mustJSON(t, raw, &out)
	if !out.Fixture {
		t.Fatalf("fixture test config should report fixture mode: %+v", out)
	}
	byName := map[string]string{}
	for _, b := range out.Backends {
		byName[b.Name+":"+b.Kind] = b.State
	}
	for _, k := range []string{"mock.subfinder:passive_discovery", "mock.alterx:candidate_generation", "mock.dnsx:resolver"} {
		if byName[k] != "ready_fixture" {
			t.Fatalf("%s state = %q, want ready_fixture", k, byName[k])
		}
	}
}

func TestRealModeRefusesReservedPlaceholderAtPin(t *testing.T) {
	cfg := &Config{ScopeRoot: "example.com", DataDir: t.TempDir(), Fixture: false}
	_, err := NewApp(cfg, testLogger())
	if err == nil {
		t.Fatal("real mode accepted reserved placeholder root")
	}
}

func TestRealBackendsReportMissingBinariesClearly(t *testing.T) {
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.Fixture = false
		c.Backend.ManagedBinDir = filepath.Join(t.TempDir(), "empty-bin")
	})
	_, app := connectInProcess(t, cfg)
	infos := app.BackendInfos()
	if len(infos) == 0 {
		t.Fatal("no backend infos")
	}
	for _, info := range infos {
		if info.Name == "subfinder" || info.Name == "dnsx" || info.Name == "alterx" {
			if info.License == "" || info.LicenseVerified {
				t.Fatalf("license should be static metadata, not runtime-verified: %+v", info)
			}
			if info.State != "unverified" || info.Notes == "" {
				t.Fatalf("missing binary should be reported clearly: %+v", info)
			}
		}
	}
	err := app.verifyRealBackends()
	if err == nil {
		t.Fatal("verification should fail when binaries are missing")
	}
}

func TestRealBackendsReportHashMismatchClearly(t *testing.T) {
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.Fixture = false
		c.Backend.ManagedBinDir = filepath.Join(t.TempDir(), "empty-bin")
	})
	_, app := connectInProcess(t, cfg)
	app.verifyPinnedBinary = func(name, path string) (adapters.PinnedTool, string, error) {
		return adapters.PinnedTool{}, "", fmt.Errorf("hash mismatch for %s at %s", name, path)
	}
	// Point binPaths at fake existing files by overriding config paths.
	dir := t.TempDir()
	for _, name := range []string{"subfinder", "dnsx", "alterx"} {
		p := filepath.Join(dir, name)
		if err := writeTestFile(p); err != nil {
			t.Fatal(err)
		}
	}
	app.cfg.Backend.SubfinderBin = filepath.Join(dir, "subfinder")
	app.cfg.Backend.DnsxBin = filepath.Join(dir, "dnsx")
	app.cfg.Backend.AlterxBin = filepath.Join(dir, "alterx")
	err := app.verifyRealBackends()
	if err == nil || !strings.Contains(err.Error(), "hash mismatch") {
		t.Fatalf("expected hash mismatch error, got %v", err)
	}
}

func writeTestFile(path string) error {
	return os.WriteFile(path, []byte("not a backend"), 0o600)
}
