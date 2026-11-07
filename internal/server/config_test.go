package server

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadConfigResolvesDefaultAuthorizationPath(t *testing.T) {
	env := map[string]string{EnvDataDir: "./data"}
	cfg, err := LoadConfig(func(key string) string { return env[key] })
	if err != nil {
		t.Fatalf("LoadConfig: %v", err)
	}
	dataDir, err := filepath.Abs("./data")
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dataDir, "external-authorization.json")
	if cfg.External.AuthFile != want {
		t.Fatalf("default auth path = %q, want absolute path %q", cfg.External.AuthFile, want)
	}
}

func TestLoadConfigRejectsRelativeAuthorizationOverride(t *testing.T) {
	env := map[string]string{EnvExternalAuth: filepath.Join("relative", "auth.json")}
	_, err := LoadConfig(func(key string) string { return env[key] })
	if err == nil || !strings.Contains(err.Error(), "absolute") {
		t.Fatalf("relative explicit auth path error = %v, want an absolute-path validation error", err)
	}
}
