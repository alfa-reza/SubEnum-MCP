package server

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
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

func TestBackendsDefaultDisabledAndHonest(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	raw := callTool(t, session, "list_backends", nil)
	var out BackendsOut
	mustJSON(t, raw, &out)
	if out.External.State != GateDisabled || out.External.Requested {
		t.Fatalf("external gate = %+v", out.External)
	}
	byName := map[string]backendInfoMapping{}
	for _, b := range out.Backends {
		byName[b.Name] = backendInfoMapping{state: b.State, version: b.Version}
	}
	for _, n := range []string{"mock.subfinder", "mock.alterx", "mock.dnsx"} {
		if byName[n].state != "ready_fixture" {
			t.Fatalf("%s state = %q", n, byName[n].state)
		}
	}
	for n, version := range map[string]string{"subfinder": "v2.17.0", "dnsx": "v1.3.1", "alterx": "v0.1.0"} {
		if byName[n].state != "disabled" || byName[n].version != version {
			t.Fatalf("%s must report its compiled release pin while disabled: %+v", n, byName[n])
		}
	}
}

type backendInfoMapping struct {
	state   string
	version string
}

func TestExternalGateRefusesExampleCom(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "external-authorization.json")
	auth := `{"authorized": true, "operator": "platform-team", "scope_root": "example.com", "acknowledgement": "authorized for this scope"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, func(c *Config) {
		c.External.Requested = true
		c.External.AuthFile = authFile
		c.External.SubfinderBin = "/opt/subfinder"
		c.External.DnsxBin = "/opt/dnsx"
		c.External.AlterxBin = "/opt/alterx"
	})
	session, app := connectInProcess(t, cfg)

	raw := callTool(t, session, "list_backends", nil)
	var out BackendsOut
	mustJSON(t, raw, &out)
	if out.External.State != GateRefused || !out.External.RootPlaceholder {
		t.Fatalf("placeholder root must be refused by external gate: %+v", out.External)
	}
	for _, reason := range out.External.Reasons {
		if strings.Contains(reason, "placeholder") {
			return
		}
	}
	t.Fatalf("refusal reason missing: %+v", out.External.Reasons)
	_ = app
}

func TestExternalGateRequiresAuthorizationAndPinning(t *testing.T) {
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.External.Requested = true
	})
	session, _ := connectInProcess(t, cfg)
	raw := callTool(t, session, "list_backends", nil)
	var out BackendsOut
	mustJSON(t, raw, &out)
	if out.External.Authorized {
		t.Fatalf("authorization file missing, but gate reports authorized: %+v", out.External)
	}
	if out.External.State != GateRefused {
		t.Fatalf("unauthorized gate state = %q", out.External.State)
	}

	// With authorization + binaries configured, the gate is honest about
	// unverified versions/styles and execution stays blocked.
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	auth := `{"authorized": true, "operator": "secops", "scope_root": "corp.customer-example.net", "acknowledgement": "I confirm authorization for passive DNS enumeration of this scope"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg2 := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.External.Requested = true
		c.External.AuthFile = authFile
		c.External.SubfinderBin = "/opt/subfinder"
		c.External.DnsxBin = "/opt/dnsx"
		c.External.AlterxBin = "/opt/alterx"
	})
	session2, app2 := connectInProcess(t, cfg2)
	raw = callTool(t, session2, "list_backends", nil)
	mustJSON(t, raw, &out)
	if out.External.State != GateUnverified || out.External.Authorized != true {
		t.Fatalf("unverified gate = %+v", out.External)
	}
	if _, err := app2.externalDiscover(context.Background()); err == nil {
		t.Fatal("external discovery executed while backend versions are unverified")
	}
}

func TestExternalGateRequiresPinnedBinaryDigests(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	auth := `{"authorized": true, "operator": "secops", "scope_root": "corp.customer-example.net", "acknowledgement": "authorized for passive enumeration"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	bins := map[string]string{}
	for _, name := range []string{"subfinder", "dnsx", "alterx"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("not the pinned release payload"), 0o700); err != nil {
			t.Fatal(err)
		}
		bins[name] = path
	}
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.External.Requested = true
		c.External.AuthFile = authFile
		c.External.SubfinderBin = bins["subfinder"]
		c.External.DnsxBin = bins["dnsx"]
		c.External.AlterxBin = bins["alterx"]
		c.External.LiveEnabled = true
	})
	session, app := connectInProcess(t, cfg)
	raw := callTool(t, session, "list_backends", nil)
	var out BackendsOut
	mustJSON(t, raw, &out)
	if out.External.State != GateUnverified || out.External.Pinned || out.External.BinariesVerified {
		t.Fatalf("operator-supplied executable hashes must not satisfy the compiled pin = %+v", out.External)
	}
	if _, err := app.externalDiscover(context.Background()); err == nil {
		t.Fatal("external discovery executed with a mismatched pinned binary")
	}
}

func TestAuthorizationScopeMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	auth := `{"authorized": true, "operator": "secops", "scope_root": "other.example.org", "acknowledgement": "ok"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuthorization(authFile, "real.example.net"); err == nil {
		t.Fatal("scope mismatch accepted")
	}
	if err := os.WriteFile(authFile, []byte(`{authorized: not-json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ReadAuthorization(authFile, "real.example.net"); err == nil {
		t.Fatal("malformed authorization accepted")
	}
}

func TestExternalGateReasonsAreDeterministic(t *testing.T) {
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	auth := `{"authorized":true,"operator":"secops","scope_root":"corp.customer-example.net","acknowledgement":"authorized"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = "corp.customer-example.net"
		c.External.Requested = true
		c.External.AuthFile = authFile
		c.External.SubfinderBin = "/pinned/subfinder"
		c.External.DnsxBin = "/pinned/dnsx"
		c.External.AlterxBin = "/pinned/alterx"
	})
	_, app := connectInProcess(t, cfg)
	app.verifyPinnedBinary = func(name, path string) (adapters.PinnedTool, string, error) {
		return adapters.PinnedTool{}, "", fmt.Errorf("bad %s", name)
	}
	want := []string{"bad subfinder", "bad dnsx", "bad alterx"}
	for i := 0; i < 50; i++ {
		gate := app.externalGate()
		if gate.State != GateUnverified || !reflect.DeepEqual(gate.Reasons, want) {
			t.Fatalf("iteration %d: external gate = %+v, want stable reasons %v", i, gate, want)
		}
	}
}
