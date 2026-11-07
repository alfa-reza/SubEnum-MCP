package server

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func TestRealToolsDispatchThroughMCPWithOfflineFakes(t *testing.T) {
	root := "corp.customer-example.net"
	dir := t.TempDir()
	bins := map[string]string{}
	for _, name := range []string{"subfinder", "dnsx", "alterx"} {
		bins[name] = filepath.Join(dir, name)
	}
	cfg := testConfig(t, func(c *Config) {
		c.ScopeRoot = root
		c.Fixture = false
		c.Backend.SubfinderBin = bins["subfinder"]
		c.Backend.DnsxBin = bins["dnsx"]
		c.Backend.AlterxBin = bins["alterx"]
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
		return adapters.PinnedTool{Name: name, Version: "test-pin", License: "MIT", Platform: "linux/amd64"}, "test-digest", nil
	}

	raw := callTool(t, session, "discover_subdomains", map[string]any{"max_records": 5, "timeout_seconds": 10})
	var discover DiscoverOut
	mustJSON(t, raw, &discover)
	if discover.Mode != "real" || discover.Fixture || discover.Count != 1 || discover.Records[0].Host != "api."+root {
		t.Fatalf("real discover output = %+v", discover)
	}
	if discover.Records[0].Provenance[0].Fixture {
		t.Fatalf("real discovery was mislabeled fixture: %+v", discover.Records[0])
	}

	raw = callTool(t, session, "generate_candidates", map[string]any{"run_id": discover.RunID, "max_candidates": 5, "timeout_seconds": 10})
	var generate GenerateOut
	mustJSON(t, raw, &generate)
	if generate.Mode != "real" || generate.Fixture || generate.Generated != 1 || generate.Records[0].Host != "v2.api."+root {
		t.Fatalf("real candidate output = %+v", generate)
	}

	raw = callTool(t, session, "resolve_hosts", map[string]any{"run_id": discover.RunID, "hosts": []string{"api." + root, "fake" + root}, "max_hosts": 5, "timeout_seconds": 10})
	var resolve ResolveOut
	mustJSON(t, raw, &resolve)
	if resolve.Mode != "real" || resolve.Fixture || resolve.Accepted != 1 || resolve.StatusCounts[string(model.StatusResolved)] != 1 {
		t.Fatalf("real resolve output = %+v", resolve)
	}
	if len(resolve.Dropped) != 1 || resolve.Dropped[0].Reason == "" {
		t.Fatalf("out-of-scope host was not rejected before dnsx: %+v", resolve.Dropped)
	}

	raw = callTool(t, session, "bruteforce_subdomains", map[string]any{"run_id": discover.RunID, "wordlist": "preset-small", "max_words": 2, "timeout_seconds": 10})
	var brute BruteforceOut
	mustJSON(t, raw, &brute)
	if brute.Mode != "real" || brute.Fixture || brute.WordsQueried != 2 {
		t.Fatalf("real brute-force output = %+v", brute)
	}
	if len(seen) != 4 {
		t.Fatalf("runner calls=%d, want 4: %+v", len(seen), seen)
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
	if !out.Fixture || out.Mode != "fixture" {
		t.Fatalf("default timeout fixture call = %+v", out)
	}
}
