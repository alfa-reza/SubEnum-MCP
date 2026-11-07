package server

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func TestExternalToolsDispatchThroughMCPWithOfflineFakes(t *testing.T) {
	root := "corp.customer-example.net"
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	auth := `{"authorized":true,"operator":"test-operator","scope_root":"` + root + `","acknowledgement":"test fixture only; no real network"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	bins := map[string]string{}
	for _, name := range []string{"subfinder", "dnsx", "alterx"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("fake executable placeholder"), 0o700); err != nil {
			t.Fatal(err)
		}
		bins[name] = path
	}
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = root
		c.External.Requested = true
		c.External.LiveEnabled = true
		c.External.AuthFile = authFile
		c.External.SubfinderBin = bins["subfinder"]
		c.External.DnsxBin = bins["dnsx"]
		c.External.AlterxBin = bins["alterx"]
	})
	session, app := connectInProcess(t, cfg)

	var seen []adapters.ExecSpec
	fake := &adapters.FakeRunner{Fn: func(spec adapters.ExecSpec) ([]byte, []byte, error) {
		seen = append(seen, spec)
		switch spec.PinnedBackend {
		case "subfinder":
			joined := strings.Join(spec.Args, " ")
			if strings.Contains(joined, "-active") || strings.Contains(joined, "-nW") {
				return nil, nil, errors.New("active Subfinder flag was passed")
			}
			return []byte("{\"host\":\"api." + root + "\"}\n"), nil, nil
		case "alterx":
			return []byte("v2.api." + root + "\n"), nil, nil
		case "dnsx":
			for i, arg := range spec.Args {
				if arg == "-w" && i+1 < len(spec.Args) {
					data, err := os.ReadFile(spec.Args[i+1])
					if err != nil {
						return nil, nil, err
					}
					if strings.TrimSpace(string(data)) == "" {
						return nil, nil, errors.New("server preset wordlist was empty")
					}
					return []byte("{\"host\":\"api." + root + "\",\"a\":[\"192.0.2.12\"]}\n"), nil, nil
				}
			}
			if spec.Stdin == "api."+root+"\n" {
				return []byte("{\"host\":\"api." + root + "\",\"a\":[\"192.0.2.12\"]}\n"), nil, nil
			}
			return nil, nil, errors.New("unexpected dnsx input")
		default:
			return nil, nil, errors.New("unknown pinned backend")
		}
	}}
	app.runner = fake
	external, err := adapters.NewExternalBackends(app.scope, app.builder, fake)
	if err != nil {
		t.Fatal(err)
	}
	app.external = external
	app.verifyPinnedBinary = func(name, path string) (adapters.PinnedTool, string, error) {
		if path != bins[name] {
			return adapters.PinnedTool{}, "", errors.New("unexpected binary path")
		}
		return adapters.PinnedTool{Name: name, Version: "test-pin", License: "MIT", Platform: "linux/amd64"}, "test-digest", nil
	}

	raw := callTool(t, session, "discover_subdomains", map[string]any{"max_records": 5, "timeout_seconds": 10})
	var discover DiscoverOut
	mustJSON(t, raw, &discover)
	if discover.Mode != externalMode || discover.Fixture || discover.Count != 1 || discover.Records[0].Host != "api."+root || discover.Backend.Name != "subfinder" {
		t.Fatalf("external discover output = %+v", discover)
	}
	if discover.Records[0].Provenance[0].Fixture {
		t.Fatalf("external discovery was mislabeled fixture: %+v", discover.Records[0])
	}

	raw = callTool(t, session, "generate_candidates", map[string]any{"run_id": discover.RunID, "max_candidates": 5, "timeout_seconds": 10})
	var generate GenerateOut
	mustJSON(t, raw, &generate)
	if generate.Mode != externalMode || generate.Fixture || generate.Generated != 1 || generate.Records[0].Host != "v2.api."+root || generate.Backend.Name != "alterx" {
		t.Fatalf("external candidate output = %+v", generate)
	}

	raw = callTool(t, session, "resolve_hosts", map[string]any{"run_id": discover.RunID, "hosts": []string{"api." + root, "fake" + root}, "max_hosts": 5, "timeout_seconds": 10})
	var resolve ResolveOut
	mustJSON(t, raw, &resolve)
	if resolve.Mode != externalMode || resolve.Fixture || resolve.Accepted != 1 || resolve.StatusCounts[string(model.StatusResolved)] != 1 || resolve.Backend.Name != "dnsx" {
		t.Fatalf("external resolve output = %+v", resolve)
	}
	if len(resolve.Dropped) != 1 || resolve.Dropped[0].Reason == "" {
		t.Fatalf("out-of-scope host was not rejected before dnsx: %+v", resolve.Dropped)
	}

	raw = callTool(t, session, "bruteforce_subdomains", map[string]any{"run_id": discover.RunID, "wordlist": "preset-small", "max_words": 2, "timeout_seconds": 10})
	var brute BruteforceOut
	mustJSON(t, raw, &brute)
	if brute.Mode != externalMode || brute.Fixture || brute.WordsQueried != 2 || brute.Backend.Name != "dnsx" {
		t.Fatalf("external brute-force output = %+v", brute)
	}
	if len(seen) != 4 {
		t.Fatalf("external runner calls=%d, want 4: %+v", len(seen), seen)
	}
	want := []string{"subfinder", "alterx", "dnsx", "dnsx"}
	for i, spec := range seen {
		if spec.PinnedBackend != want[i] || spec.Timeout != 10*time.Second {
			t.Fatalf("runner call %d = %+v", i, spec)
		}
		if strings.Contains(spec.Describe(), "sh -c") {
			t.Fatalf("shell invocation found in external spec: %+v", spec)
		}
	}
}

func TestExternalLiveGateBlocksNetworkButAllowsLocalAlterX(t *testing.T) {
	root := "corp.customer-example.net"
	dir := t.TempDir()
	authFile := filepath.Join(dir, "auth.json")
	auth := `{"authorized":true,"operator":"test-operator","scope_root":"` + root + `","acknowledgement":"offline unit test only"}`
	if err := os.WriteFile(authFile, []byte(auth), 0o600); err != nil {
		t.Fatal(err)
	}
	bins := map[string]string{}
	for _, name := range []string{"subfinder", "dnsx", "alterx"} {
		path := filepath.Join(dir, name)
		if err := os.WriteFile(path, []byte("fake executable placeholder"), 0o700); err != nil {
			t.Fatal(err)
		}
		bins[name] = path
	}
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = root
		c.External.Requested = true
		c.External.LiveEnabled = false
		c.External.AuthFile = authFile
		c.External.SubfinderBin = bins["subfinder"]
		c.External.DnsxBin = bins["dnsx"]
		c.External.AlterxBin = bins["alterx"]
	})
	session, app := connectInProcess(t, cfg)
	fake := &adapters.FakeRunner{Fn: func(spec adapters.ExecSpec) ([]byte, []byte, error) {
		if spec.PinnedBackend != "alterx" {
			return nil, nil, errors.New("network backend reached while live gate was off")
		}
		return []byte("new-api." + root + "\n"), nil, nil
	}}
	app.runner = fake
	external, err := adapters.NewExternalBackends(app.scope, app.builder, fake)
	if err != nil {
		t.Fatal(err)
	}
	app.external = external
	app.verifyPinnedBinary = func(name, path string) (adapters.PinnedTool, string, error) {
		if path != bins[name] {
			return adapters.PinnedTool{}, "", errors.New("unexpected binary path")
		}
		return adapters.PinnedTool{Name: name, Version: "test-pin", License: "MIT", Platform: "linux/amd64"}, "test-digest", nil
	}
	run, err := app.runForWrite("")
	if err != nil {
		t.Fatal(err)
	}
	seed := model.NewRecord(run.ID, "api."+root, model.StatusCandidate, model.Provenance{
		Backend: "test", Method: "seed", Detail: "offline seed", Fixture: false,
	}, true, "")
	if _, err := run.Upsert(seed); err != nil {
		t.Fatal(err)
	}
	raw := callTool(t, session, "generate_candidates", map[string]any{"run_id": run.ID, "timeout_seconds": 10})
	var generated GenerateOut
	mustJSON(t, raw, &generated)
	if generated.Mode != externalMode || generated.Fixture || generated.Generated != 1 || generated.Records[0].Host != "new-api."+root {
		t.Fatalf("local AlterX dispatch with live gate off = %+v", generated)
	}
	errText := callToolErr(t, session, "discover_subdomains", map[string]any{"run_id": run.ID})
	if !strings.Contains(errText, EnvLiveEnable) || fake.CallCount() != 1 {
		t.Fatalf("network operation was not blocked before runner: error=%q calls=%d", errText, fake.CallCount())
	}
}

func TestToolTimeoutSecondsHardCapAndDefault(t *testing.T) {
	session, _ := connectInProcess(t, testConfig(t, nil))
	for _, value := range []int{-1, CapMaxTimeoutSeconds + 1} {
		message := callToolErr(t, session, "discover_subdomains", map[string]any{"timeout_seconds": value})
		bound := "maximum"
		if value < 0 {
			bound = "minimum"
		}
		if !strings.Contains(message, "timeout_seconds") || !strings.Contains(message, bound) {
			t.Fatalf("timeout_seconds=%d error=%q", value, message)
		}
	}
	raw := callTool(t, session, "discover_subdomains", map[string]any{"timeout_seconds": 0})
	var out DiscoverOut
	mustJSON(t, raw, &out)
	if !out.Fixture || out.Mode != fixtureMode {
		t.Fatalf("default timeout fixture call = %+v", out)
	}
}
