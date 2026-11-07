package server

import (
	"path/filepath"
	"testing"
)

func TestLoadConfigDefaults(t *testing.T) {
	cfg, err := LoadConfig(func(string) string { return "" })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ScopeRoot != "" {
		t.Fatalf("default scope = %q, want empty (unpinned)", cfg.ScopeRoot)
	}
	if !cfg.ScopeDataDir {
		t.Fatal("default config should use per-scope data directories")
	}
	if cfg.DataDir == "" || !filepath.IsAbs(cfg.DataDir) {
		t.Fatalf("data dir = %q, want absolute default", cfg.DataDir)
	}
	if cfg.Backend.ManagedBinDir == "" {
		t.Fatal("managed bin dir should be set")
	}
}

func TestLoadConfigExplicitDataDirDisablesScopeSplit(t *testing.T) {
	env := map[string]string{EnvDataDir: t.TempDir(), EnvScopeRoot: "example.com"}
	cfg, err := LoadConfig(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	if cfg.ScopeDataDir {
		t.Fatal("explicit data dir should be used directly")
	}
	if cfg.ScopeRoot != "example.com" {
		t.Fatalf("scope root = %q", cfg.ScopeRoot)
	}
}
