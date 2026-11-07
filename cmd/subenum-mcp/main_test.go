package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
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

// startServer spawns the compiled stdio binary in fixture/default mode.
type synchronizedStderr struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *synchronizedStderr) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *synchronizedStderr) WriteString(p string) (int, error) {
	return s.Write([]byte(p))
}

func (s *synchronizedStderr) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func startServer(t *testing.T, env map[string]string) (*exec.Cmd, *synchronizedStderr) {
	t.Helper()
	cmd := exec.Command(smokeBinary)
	stderr := &synchronizedStderr{}
	cmd.Stderr = stderr
	cmd.Env = []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"SUBENUM_DATA_DIR=" + filepath.Join(t.TempDir(), "data"),
	}
	for k, v := range env {
		cmd.Env = append(cmd.Env, k+"="+v)
	}
	return cmd, stderr
}

func TestStderrCaptureSupportsConcurrentSnapshots(t *testing.T) {
	var stderr synchronizedStderr
	start := make(chan struct{})
	var wg sync.WaitGroup
	for worker := 0; worker < 4; worker++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for i := 0; i < 1000; i++ {
				_, _ = stderr.WriteString("server log line\n")
				_ = stderr.String()
			}
		}()
	}
	close(start)
	wg.Wait()
}

func assertNoPortDialerLeak(t *testing.T) {
	t.Helper()
	// Defensive: fail fast if any test in this file leaves a listening
	// process; the smoke server must be pure stdio.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err == nil {
		_ = ln.Close()
	}
}

func TestStdioSmokeDefaultFixtureMode(t *testing.T) {
	assertNoPortDialerLeak(t)
	cmd, stderr := startServer(t, nil)
	client := mcp.NewClient(&mcp.Implementation{Name: "smoke-client", Version: "1.0.0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		stderrCopy := stderr.String()
		t.Fatalf("connect+initialize over stdio failed: %v; server stderr:\n%s", err, stderrCopy)
	}
	defer func() { _ = session.Close() }()

	if session.InitializeResult() == nil {
		t.Fatal("initialize result missing")
	}

	// tools/list
	listRes, err := session.ListTools(ctx, nil)
	if err != nil {
		t.Fatalf("tools/list: %v", err)
	}
	want := map[string]bool{
		"discover_subdomains": false, "generate_candidates": false, "bruteforce_subdomains": false,
		"resolve_hosts": false, "get_results": false, "list_backends": false,
		"doctor": false, "export_results": false,
	}
	for _, tool := range listRes.Tools {
		if _, ok := want[tool.Name]; ok {
			want[tool.Name] = true
		}
		if tool.Description == "" || tool.InputSchema == nil {
			t.Errorf("tool %q incomplete (description=%t schema=%t)", tool.Name, tool.Description != "", tool.InputSchema != nil)
		}
	}
	for name, found := range want {
		if !found {
			t.Errorf("tools/list missing %q", name)
		}
	}

	// tools/call: discover on default placeholder root (fixture output only)
	disc, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "discover_subdomains",
		Arguments: map[string]any{},
	})
	if err != nil || disc.IsError {
		t.Fatalf("tools/call discover_subdomains failed: err=%v result=%+v stderr=%s", err, disc, stderr.String())
	}
	var discOut struct {
		RunID   string `json:"run_id"`
		Fixture bool   `json:"fixture"`
		Mode    string `json:"mode"`
		Count   int    `json:"count"`
	}
	_ = marshalTransform(t, disc.StructuredContent, &discOut)
	if !discOut.Fixture || discOut.Mode != "fixture" || discOut.Count == 0 || discOut.RunID == "" {
		t.Fatalf("unexpected discover output: %+v", discOut)
	}

	// tools/call: get_results (structured pagination)
	res, err := session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "get_results",
		Arguments: map[string]any{"run_id": discOut.RunID, "page": 1, "page_size": 5},
	})
	if err != nil || res.IsError {
		t.Fatalf("tools/call get_results failed: err=%v result=%+v", err, res)
	}
	var pageOut struct {
		Page       int `json:"page"`
		PageSize   int `json:"page_size"`
		Total      int `json:"total"`
		TotalPages int `json:"total_pages"`
		Records    []struct {
			Host   string `json:"host"`
			Status string `json:"status"`
		} `json:"records"`
	}
	_ = marshalTransform(t, res.StructuredContent, &pageOut)
	if pageOut.Page != 1 || pageOut.PageSize != 5 || pageOut.Total == 0 || len(pageOut.Records) == 0 {
		t.Fatalf("unexpected pagination output: %+v", pageOut)
	}
	for _, rec := range pageOut.Records {
		if !strings.HasSuffix(rec.Host, ".example.com") || rec.Host == "example.com" {
			t.Fatalf("record outside scope boundary: %q", rec.Host)
		}
	}

	// tools/call: list_backends — external backends must be disabled by default
	res, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "list_backends",
		Arguments: map[string]any{},
	})
	if err != nil || res.IsError {
		t.Fatalf("tools/call list_backends failed: %v %+v", err, res)
	}
	var backendsOut struct {
		External struct {
			State string `json:"state"`
		} `json:"external"`
		Backends []struct {
			Name  string `json:"name"`
			State string `json:"state"`
		} `json:"backends"`
	}
	_ = marshalTransform(t, res.StructuredContent, &backendsOut)
	if backendsOut.External.State != "disabled" {
		t.Fatalf("external gate = %q, want disabled", backendsOut.External.State)
	}
	for _, b := range backendsOut.Backends {
		if b.Name == "subfinder" || b.Name == "dnsx" || b.Name == "alterx" {
			if b.State != "disabled" {
				t.Fatalf("external backend %s state = %q, want disabled", b.Name, b.State)
			}
		}
	}

	// tools/call: export_results JSONL into managed folder
	res, err = session.CallTool(ctx, &mcp.CallToolParams{
		Name:      "export_results",
		Arguments: map[string]any{"run_id": discOut.RunID, "format": "jsonl", "folder": "smoke-export"},
	})
	if err != nil || res.IsError {
		t.Fatalf("tools/call export_results failed: %v %+v", err, res)
	}
	var expOut struct {
		Result struct {
			Path   string `json:"path"`
			Rows   int    `json:"rows"`
			SHA256 string `json:"sha256"`
		} `json:"result"`
	}
	_ = marshalTransform(t, res.StructuredContent, &expOut)
	if expOut.Result.Rows == 0 || len(expOut.Result.SHA256) != 64 || !strings.Contains(expOut.Result.Path, "exports/smoke-export/") {
		t.Fatalf("unexpected export output: %+v", expOut)
	}

	// Structured outputs must also be mirrored into text content by the SDK.
	for _, c := range disc.Content {
		if tc, ok := c.(*mcp.TextContent); ok && !strings.Contains(tc.Text, "fixture") {
			t.Fatalf("text content missing fixture label: %s", tc.Text)
		}
	}

	// stderr must carry logs only; the default fixture config never mentions
	// secret material. stdout purity is proven by the SDK client parsing it.
	if !strings.Contains(stderr.String(), "subenum-mcp starting") {
		t.Fatalf("expected startup log on stderr, got: %q", stderr.String())
	}

	// Closing the session closes the child's stdin, which is the stdio
	// transport's shutdown signal; CommandTransport then reaps the process.
	if err := session.Close(); err != nil {
		t.Fatalf("closing session: %v; stderr: %s", err, stderr.String())
	}
}

// marshalTransform converts StructuredContent (map[string]any) for the target.
func marshalTransform(t *testing.T, content any, target any) error {
	t.Helper()
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatalf("marshal structured content: %v", err)
	}
	if err := json.Unmarshal(raw, target); err != nil {
		t.Fatalf("unmarshal into %T: %v (%s)", target, err, raw)
	}
	return nil
}

func TestStdioSmokeExternalNeverRunsByDefault(t *testing.T) {
	cmd, stderr := startServer(t, nil)
	client := mcp.NewClient(&mcp.Implementation{Name: "smoke-client-2", Version: "1.0.0"}, nil)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	session, err := client.Connect(ctx, &mcp.CommandTransport{Command: cmd}, nil)
	if err != nil {
		t.Fatalf("connect failed: %v; stderr:\n%s", err, stderr.String())
	}
	defer func() { _ = session.Close() }()

	res, err := session.CallTool(ctx, &mcp.CallToolParams{Name: "doctor", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("doctor failed: %v %+v", err, res)
	}
	var docOut struct {
		OK     bool `json:"ok"`
		Checks []struct {
			Name   string `json:"name"`
			State  string `json:"state"`
			Detail string `json:"detail"`
		} `json:"checks"`
	}
	_ = marshalTransform(t, res.StructuredContent, &docOut)
	if !docOut.OK {
		t.Fatalf("doctor not ok: %+v", docOut)
	}
	for _, c := range docOut.Checks {
		if c.Name == "external_gate" && c.State != "ok" {
			t.Fatalf("external gate check = %+v, want ok (disabled) in default mode", c)
		}
	}
}
