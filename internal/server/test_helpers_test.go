package server

import (
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(&slw{}, &slog.HandlerOptions{Level: slog.LevelError}))
}

type slw struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (w *slw) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}

func (w *slw) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func testConfig(t *testing.T, mutate func(*Config)) *Config {
	t.Helper()
	dir := t.TempDir()
	cfg := &Config{
		ScopeRoot: "example.com",
		DataDir:   dir,
		Fixture:   true,
	}
	if mutate != nil {
		mutate(cfg)
	}
	return cfg
}

// connectInProcess spins up an in-memory MCP session against a fresh App.
func connectInProcess(t *testing.T, cfg *Config) (*mcp.ClientSession, *App) {
	t.Helper()
	app, err := NewApp(cfg, testLogger())
	if err != nil {
		t.Fatalf("NewApp: %v", err)
	}
	srv := mcp.NewServer(&mcp.Implementation{Name: "subenum-mcp", Version: "0.1.0-dev.1"}, nil)
	app.Register(srv)

	clientTransport, serverTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	go func() { _ = srv.Run(ctx, serverTransport) }()

	client := mcp.NewClient(&mcp.Implementation{Name: "subenum-test-client", Version: "1.0.0"}, nil)
	session, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		t.Fatalf("client connect (initialize handshake): %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	t.Cleanup(func() { _ = session.Close() })
	return session, app
}

func callTool(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) json.RawMessage {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s: %v", name, err)
	}
	if res.IsError {
		text := ""
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text += tc.Text
			}
		}
		t.Fatalf("tools/call %s returned tool error: %s", name, text)
	}
	if res.StructuredContent == nil {
		t.Fatalf("tools/call %s returned no structured content", name)
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	return json.RawMessage(raw)
}

func callToolErr(t *testing.T, session *mcp.ClientSession, name string, args map[string]any) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("tools/call %s: protocol error: %v", name, err)
	}
	if !res.IsError {
		t.Fatalf("tools/call %s: expected tool error", name)
	}
	text := ""
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			text += tc.Text
		}
	}
	return text
}

func intPtr(i int) *int       { return &i }
func strPtr(s string) *string { return &s }

func mustJSON(t *testing.T, raw json.RawMessage, out any) {
	t.Helper()
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("invalid structured output %s: %v", raw, err)
	}
}

func bigHostList(n int) []string {
	out := make([]string, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, "h"+strings.Repeat("x", 30)+"-"+itoa(i)+".example.com")
	}
	return out
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		digits = string(rune('0'+i%10)) + digits
		i /= 10
	}
	return digits
}
