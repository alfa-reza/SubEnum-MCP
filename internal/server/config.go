// Package server wires the enumeration tools into an MCP server.
package server

import (
	"bytes"
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
)

// Environment variables.
const (
	EnvScopeRoot     = "SUBENUM_SCOPE_ROOT"
	EnvDataDir       = "SUBENUM_DATA_DIR"
	EnvSubfinderBin  = "SUBENUM_SUBFINDER_BIN"
	EnvDnsxBin       = "SUBENUM_DNSX_BIN"
	EnvAlterxBin     = "SUBENUM_ALTERX_BIN"
	EnvDnsxResolvers = "SUBENUM_DNSX_RESOLVERS"
)

// DefaultRoot is the reserved placeholder scope root, used only for
// explicitly requested fixture/test mode. Real enumeration refuses reserved
// placeholder roots. Servers normally start unpinned and pin a scope at the
// first start_run call; SUBENUM_SCOPE_ROOT may optionally pre-pin.
const DefaultRoot = "example.com"
const (
	CapMaxRecordsPerCall   = 5000
	DefaultDiscoverRecords = 100
	CapMaxCandidates       = 5000
	CapMaxBruteforceWords  = 1000
	CapMaxResolveHosts     = 2000
	CapMaxSeedHosts        = 2000
	CapMaxPageSize         = 1000
	CapDefaultPageSize     = 100
	CapMaxTimeoutSeconds   = 300
	DefaultTimeoutSeconds  = 120
)

type BackendConfig struct {
	SubfinderBin  string
	DnsxBin       string
	AlterxBin     string
	ManagedBinDir string
	DnsxResolvers string
}

type Config struct {
	ScopeRoot string
	DataDir   string
	// ScopeDataDir selects a separate managed data directory for each scope.
	ScopeDataDir bool
	// Fixture runs the in-process, clearly labeled offline test backends.
	// It is for tests and local development, not real enumeration.
	Fixture bool
	Backend BackendConfig
}

func LoadConfig(getenv func(string) string) (*Config, error) {
	// No scope default: an unset scope starts the server unpinned; the first
	// start_run pins it. SUBENUM_SCOPE_ROOT pre-pins for operators that want
	// a fixed root without going through tool input.
	root := strings.TrimSpace(getenv(EnvScopeRoot))
	appHome, err := appHomeDir(getenv)
	if err != nil {
		return nil, err
	}
	managedBinDir := filepath.Join(appHome, "bin")
	dataDir := strings.TrimSpace(getenv(EnvDataDir))
	scopeDataDir := dataDir == ""
	if dataDir == "" {
		dataDir = filepath.Join(appHome, "data")
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve %s to an absolute path: %w", EnvDataDir, err)
	}
	dataDir = filepath.Clean(dataDir)
	resolvers := strings.TrimSpace(getenv(EnvDnsxResolvers))
	if resolvers == "" {
		// Default to the system's configured nameservers so a stub resolver
		// (e.g. systemd-resolved at 127.0.0.53) is used when public UDP DNS is
		// blocked. If none are readable, dnsx uses its built-in resolvers.
		resolvers = readSystemResolvers()
	}
	cfg := &Config{
		ScopeRoot:    root,
		DataDir:      dataDir,
		ScopeDataDir: scopeDataDir,
		Backend: BackendConfig{
			SubfinderBin:  strings.TrimSpace(getenv(EnvSubfinderBin)),
			DnsxBin:       strings.TrimSpace(getenv(EnvDnsxBin)),
			AlterxBin:     strings.TrimSpace(getenv(EnvAlterxBin)),
			ManagedBinDir: managedBinDir,
			DnsxResolvers: resolvers,
		},
	}
	return cfg, nil
}

// appHomeDir locates the managed home for this tool: XDG_DATA_HOME/subenum-mcp
// on Linux (e.g. ~/.local/share/subenum-mcp), otherwise ~/.local/share/subenum-mcp
// or %USERPROFILE%\\.local\\share\\subenum-mcp. It holds the data dir and the
// managed, hash-pinned backend binaries.
func appHomeDir(getenv func(string) string) (string, error) {
	if d := strings.TrimSpace(getenv("XDG_DATA_HOME")); d != "" {
		if !filepath.IsAbs(d) {
			return "", fmt.Errorf("XDG_DATA_HOME must be an absolute path, got %q", d)
		}
		return filepath.Join(d, "subenum-mcp"), nil
	}
	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		if err != nil {
			return "", fmt.Errorf("resolve home directory: %w", err)
		}
		return "", fmt.Errorf("home directory is empty; set XDG_DATA_HOME to an absolute path")
	}
	return filepath.Join(home, ".local", "share", "subenum-mcp"), nil
}

// readSystemResolvers best-effort reads /etc/resolv.conf and returns up to
// three IPv4 nameservers, comma-separated, in the format dnsx expects.
func readSystemResolvers() string {
	f, err := os.Open("/etc/resolv.conf")
	if err != nil {
		return ""
	}
	defer f.Close()
	var buf bytes.Buffer
	if _, err := io.Copy(&buf, io.LimitReader(f, 64<<10)); err != nil {
		return ""
	}
	iss := parseResolvConf(buf.String())
	return strings.Join(iss, ",")
}

// parseResolvConf extracts IPv4 nameserver entries, tolerating comments.
func parseResolvConf(content string) []string {
	var out []string
	seen := map[string]bool{}
	for _, rawLine := range strings.Split(content, "\n") {
		line := rawLine
		if i := strings.IndexAny(line, "#;"); i >= 0 {
			line = line[:i]
		}
		fields := strings.Fields(line)
		if len(fields) < 2 || !strings.EqualFold(fields[0], "nameserver") {
			continue
		}
		ip := fields[1]
		addr, err := netip.ParseAddr(ip)
		if err != nil || !addr.Is4() || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
		if len(out) == 3 {
			break
		}
	}
	return out
}
