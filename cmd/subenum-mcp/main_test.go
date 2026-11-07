package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var smokeBinary string

func TestMain(m *testing.M) {
	code := func() (exitCode int) {
		tmp, err := os.MkdirTemp("", "subenum-smoke-*")
		if err != nil {
			fmt.Fprintf(os.Stderr, "smoke setup: %v\n", err)
			return 1
		}
		defer func() {
			if err := os.RemoveAll(tmp); err != nil {
				fmt.Fprintf(os.Stderr, "smoke cleanup: %v\n", err)
				exitCode = 1
			}
		}()
		bin := filepath.Join(tmp, "subenum-mcp-smoke")
		build := exec.Command("go", "build", "-o", bin, ".")
		out, err := build.CombinedOutput()
		if err != nil {
			fmt.Fprintf(os.Stderr, "smoke build failed: %v\n%s\n", err, out)
			return 1
		}
		smokeBinary = bin
		return m.Run()
	}()
	os.Exit(code)
}

type synchronizedStderr struct {
	mu sync.Mutex
	b  strings.Builder
}

func (w *synchronizedStderr) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.Write(p)
}

func (w *synchronizedStderr) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.b.String()
}

type smokeServer struct {
	session *mcp.ClientSession
	stderr  *synchronizedStderr
	cleanup func() error
}

func startServer(t *testing.T, args []string, env ...string) *smokeServer {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)

	cmd := exec.CommandContext(ctx, smokeBinary, args...)
	cmd.Env = append(os.Environ(), env...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	var stderr synchronizedStderr
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start subenum-mcp: %v", err)
	}
	cleanup := func() error {
		_ = stdin.Close()
		err := cmd.Wait()
		if ctx.Err() != nil {
			return fmt.Errorf("smoke server did not exit before timeout: %w (stderr: %s)", ctx.Err(), stderr.String())
		}
		if err != nil {
			return fmt.Errorf("smoke server exit: %w (stderr: %s)", err, stderr.String())
		}
		return nil
	}
	t.Cleanup(func() {
		if err := cleanup(); err != nil {
			t.Error(err)
		}
	})

	client := mcp.NewClient(&mcp.Implementation{Name: "smoke-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, &mcp.IOTransport{Reader: stdout, Writer: stdin}, nil)
	if err != nil {
		if cleanupErr := cleanup(); cleanupErr != nil {
			t.Fatalf("initialize/connect failed: %v (cleanup: %v)", err, cleanupErr)
		}
		t.Fatalf("initialize/connect failed: %v (stderr: %s)", err, stderr.String())
	}
	t.Cleanup(func() { _ = session.Close() })
	return &smokeServer{session: session, stderr: &stderr, cleanup: cleanup}
}

// TestStdioSmokeFixtureMode verifies the compiled stdio server works end-to-end
// in explicit, labeled fixture/test mode (offline, deterministic).
func TestStdioSmokeFixtureMode(t *testing.T) {
	dataDir := t.TempDir()
	server := startServer(t, nil, "SUBENUM_DATA_DIR="+dataDir)
	session, stderr := server.session, server.stderr
	ctx := context.Background()

	tools, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v (stderr: %s)", err, stderr.String())
	}
	wantTools := map[string]bool{
		"start_run": false, "discover_subdomains": false, "generate_candidates": false,
		"bruteforce_subdomains": false, "resolve_hosts": false, "get_results": false,
		"list_backends": false, "doctor": false, "export_results": false,
	}
	for _, tool := range tools.Tools {
		if _, ok := wantTools[tool.Name]; ok {
			wantTools[tool.Name] = true
		}
	}
	for name, ok := range wantTools {
		if !ok {
			t.Errorf("tool %q not advertised by stdio server", name)
		}
	}

	sr, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "start_run",
		Arguments: map[string]any{"scope_root": "example.com", "fixture": true},
	})
	if err != nil || sr.IsError {
		t.Fatalf("tools/call start_run failed: err=%v result=%+v stderr=%s", err, sr, stderr.String())
	}
	var srOut struct {
		RunID string `json:"run_id"`
		Root  string `json:"root"`
	}
	mustStructured(t, sr, &srOut)
	if srOut.Root != "example.com" || srOut.RunID == "" {
		t.Fatalf("unexpected start_run output: %+v", srOut)
	}

	disc, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_subdomains",
		Arguments: map[string]any{"run_id": srOut.RunID},
	})
	if err != nil || disc.IsError {
		t.Fatalf("tools/call discover_subdomains failed: err=%v result=%+v stderr=%s", err, disc, stderr.String())
	}
	var discOut struct {
		RunID   string `json:"run_id"`
		Count   int    `json:"count"`
		Fixture bool   `json:"fixture"`
		Mode    string `json:"mode"`
	}
	mustStructured(t, disc, &discOut)
	if !discOut.Fixture || discOut.Mode != "fixture" || discOut.Count == 0 || discOut.RunID == "" {
		t.Fatalf("unexpected discover_subdomains output: %+v", discOut)
	}

	backends, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "list_backends"})
	if err != nil || backends.IsError {
		t.Fatalf("tools/call list_backends failed: err=%v result=%+v stderr=%s", err, backends, stderr.String())
	}
	var bOut struct {
		Fixture  bool `json:"fixture"`
		Pinned   bool `json:"pinned"`
		Backends []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"backends"`
	}
	mustStructured(t, backends, &bOut)
	if !bOut.Fixture || !bOut.Pinned {
		t.Fatalf("expected pinned fixture mode in list_backends: %+v", bOut)
	}

	doctor, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "doctor"})
	if err != nil || doctor.IsError {
		t.Fatalf("tools/call doctor failed: err=%v result=%+v stderr=%s", err, doctor, stderr.String())
	}
	var dOut struct {
		OK bool `json:"ok"`
	}
	mustStructured(t, doctor, &dOut)
	if !dOut.OK {
		t.Fatalf("doctor not ok in fixture smoke: %+v stderr=%s", doctor.StructuredContent, stderr.String())
	}
}

func TestStdioSmokeRealModeRefusesPlaceholder(t *testing.T) {
	dataDir := t.TempDir()
	server := startServer(t, nil, "SUBENUM_DATA_DIR="+dataDir)
	session := server.session
	ctx := context.Background()

	sr, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "start_run",
		Arguments: map[string]any{"scope_root": "example.com"},
	})
	if err != nil {
		t.Fatalf("start_run call: %v", err)
	}
	if !sr.IsError {
		t.Fatalf("real mode should refuse reserved placeholder root: %+v", sr.StructuredContent)
	}
	msg := toolText(sr)
	if !strings.Contains(msg, "reserved placeholder") {
		t.Fatalf("error = %q, want reserved placeholder refusal", msg)
	}
}

func mustStructured(t *testing.T, res *mcp.CallToolResult, out any) {
	t.Helper()
	if res == nil || res.StructuredContent == nil {
		t.Fatalf("missing structured content: %+v", res)
	}
	b, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, out); err != nil {
		t.Fatalf("decode %s: %v", b, err)
	}
}

func toolText(res *mcp.CallToolResult) string {
	if res == nil {
		return ""
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	return b.String()
}
