// Package server wires the enumeration tools into an MCP server.
package server

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

// Environment variables.
const (
	EnvScopeRoot      = "SUBENUM_SCOPE_ROOT"
	EnvDataDir        = "SUBENUM_DATA_DIR"
	EnvExternalEnable = "SUBENUM_EXTERNAL_ENABLE"
	EnvLiveEnable     = "SUBENUM_LIVE_ENABLE"
	EnvExternalAuth   = "SUBENUM_EXTERNAL_AUTH"
	EnvSubfinderBin   = "SUBENUM_SUBFINDER_BIN"
	EnvDnsxBin        = "SUBENUM_DNSX_BIN"
	EnvAlterxBin      = "SUBENUM_ALTERX_BIN"
	EnvDnsxResolvers  = "SUBENUM_DNSX_RESOLVERS"
)

// DefaultRoot is the placeholder scope root applied when no environment
// override is configured. External mode always refuses placeholder roots.
const DefaultRoot = "example.com"

// Hard caps of the server for v1.0.0.
const (
	CapMaxRecordsPerCall  = 5000
	CapMaxCandidates      = 5000
	CapMaxBruteforceWords = 1000
	CapMaxResolveHosts    = 2000
	CapMaxSeedHosts       = 2000
	CapMaxPageSize        = 1000
	CapDefaultPageSize    = 100
	CapMaxTimeoutSeconds  = 300
	DefaultTimeoutSeconds = 120
)

type ExternalConfig struct {
	Requested     bool
	LiveEnabled   bool
	SubfinderBin  string
	DnsxBin       string
	AlterxBin     string
	DnsxResolvers string
	AuthFile      string
}

type Config struct {
	ScopeRoot string
	DataDir   string
	External  ExternalConfig
}

func LoadConfig(getenv func(string) string) (*Config, error) {
	root := strings.TrimSpace(getenv(EnvScopeRoot))
	if root == "" {
		root = DefaultRoot
	}
	dataDir := strings.TrimSpace(getenv(EnvDataDir))
	if dataDir == "" {
		dataDir = "data"
	}
	dataDir, err := filepath.Abs(dataDir)
	if err != nil {
		return nil, fmt.Errorf("resolve %s to an absolute path: %w", EnvDataDir, err)
	}
	dataDir = filepath.Clean(dataDir)
	auth := strings.TrimSpace(getenv(EnvExternalAuth))
	if auth == "" {
		auth = filepath.Join(dataDir, "external-authorization.json")
	} else {
		if !filepath.IsAbs(auth) {
			return nil, fmt.Errorf("%s must be an absolute path when explicitly configured", EnvExternalAuth)
		}
		auth = filepath.Clean(auth)
	}
	cfg := &Config{
		ScopeRoot: root,
		DataDir:   dataDir,
		External: ExternalConfig{
			Requested:     strings.TrimSpace(getenv(EnvExternalEnable)) == "1",
			LiveEnabled:   strings.TrimSpace(getenv(EnvLiveEnable)) == "1",
			SubfinderBin:  strings.TrimSpace(getenv(EnvSubfinderBin)),
			DnsxBin:       strings.TrimSpace(getenv(EnvDnsxBin)),
			AlterxBin:     strings.TrimSpace(getenv(EnvAlterxBin)),
			DnsxResolvers: strings.TrimSpace(getenv(EnvDnsxResolvers)),
			AuthFile:      auth,
		},
	}
	return cfg, nil
}

// Authorization is the operator authorization document required before any
// external (non-fixture) backend may run.
type Authorization struct {
	Authorized      bool   `json:"authorized"`
	Operator        string `json:"operator"`
	ScopeRoot       string `json:"scope_root"`
	Acknowledgement string `json:"acknowledgement"`
}

func ReadAuthorization(path, scopeRoot string) (*Authorization, error) {
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("authorization file path must be absolute")
	}
	abs := filepath.Clean(path)
	parent, err := os.OpenRoot(filepath.Dir(abs))
	if err != nil {
		return nil, fmt.Errorf("authorization file %s parent cannot be opened: %w", path, err)
	}
	defer parent.Close()
	name := filepath.Base(abs)
	info, err := parent.Lstat(name)
	if err != nil {
		return nil, fmt.Errorf("authorization file %s cannot be inspected: %w", path, err)
	}
	data, err := readAuthorizationDocument(parent, name, info)
	if err != nil {
		return nil, fmt.Errorf("authorization file %s cannot be read safely: %w", path, err)
	}
	var a Authorization
	if err := json.Unmarshal(data, &a); err != nil {
		return nil, fmt.Errorf("authorization file %s is not valid JSON: %w", path, err)
	}
	if !a.Authorized {
		return nil, fmt.Errorf("authorization file %s has authorized=false; operator approval is required", path)
	}
	if strings.TrimSpace(a.Operator) == "" {
		return nil, fmt.Errorf("authorization file %s is missing the operator identity", path)
	}
	if strings.TrimSpace(a.Acknowledgement) == "" {
		return nil, fmt.Errorf("authorization file %s is missing the acknowledgement statement", path)
	}
	want := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(scopeRoot), "."))
	got := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a.ScopeRoot), "."))
	if got != want {
		return nil, fmt.Errorf("authorization file %s authorizes scope %q but this server is configured with scope %q; the two must match exactly", path, got, want)
	}
	return &a, nil
}

const maxAuthorizationBytes = 1 << 20

// readAuthorizationDocument opens through the already-anchored parent root and
// verifies that the opened file is the same regular file inspected by Lstat.
func readAuthorizationDocument(root *os.Root, name string, inspected os.FileInfo) ([]byte, error) {
	if inspected == nil || inspected.Mode()&os.ModeSymlink != 0 || !inspected.Mode().IsRegular() {
		return nil, fmt.Errorf("must be a regular non-symlink file")
	}
	if inspected.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("must not be accessible by group or other users (use mode 0600)")
	}
	f, err := root.OpenFile(name, os.O_RDONLY, 0)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	opened, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if !opened.Mode().IsRegular() || !os.SameFile(inspected, opened) {
		return nil, fmt.Errorf("file changed between inspection and open")
	}
	if opened.Mode().Perm()&0077 != 0 {
		return nil, fmt.Errorf("must not be accessible by group or other users (use mode 0600)")
	}
	data, err := io.ReadAll(io.LimitReader(f, maxAuthorizationBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxAuthorizationBytes {
		return nil, fmt.Errorf("exceeds the %d-byte authorization file limit", maxAuthorizationBytes)
	}
	return data, nil
}

// Gate states for external backends.
const (
	GateDisabled   = "disabled"
	GateRefused    = "refused"
	GateUnverified = "unverified"
	GateReady      = "ready"
)

// ExternalGate summarizes why external mode is (or is not) allowed. Gate
// evaluation reads files and hashes but never executes binaries or touches the
// network. Network-capable tools also require the separate LiveEnabled gate.
type ExternalGate struct {
	State              string   `json:"state"`
	Requested          bool     `json:"requested"`
	LiveEnabled        bool     `json:"live_enabled"`
	Authorized         bool     `json:"authorized"`
	RootPlaceholder    bool     `json:"root_placeholder_rejected"`
	BinariesConfigured bool     `json:"binaries_configured"`
	BinariesVerified   bool     `json:"binaries_verified"`
	Pinned             bool     `json:"pinned"`
	Reasons            []string `json:"reasons"`
}

func (a *App) externalGate() ExternalGate {
	g := ExternalGate{State: GateDisabled, Requested: a.cfg.External.Requested, LiveEnabled: a.cfg.External.LiveEnabled}
	if !a.cfg.External.Requested {
		g.Reasons = append(g.Reasons, fmt.Sprintf("%s is not set to 1; fixture backends remain the default", EnvExternalEnable))
		return g
	}
	if scope.IsReservedPlaceholder(a.scope.Root()) {
		g.RootPlaceholder = true
		g.State = GateRefused
		g.Reasons = append(g.Reasons, fmt.Sprintf("scope root %q is a reserved placeholder name; external mode refuses placeholders such as %s", a.scope.Root(), DefaultRoot))
		return g
	}
	if _, err := ReadAuthorization(a.cfg.External.AuthFile, a.scope.Root()); err != nil {
		g.State = GateRefused
		g.Reasons = append(g.Reasons, err.Error())
		return g
	}
	g.Authorized = true
	paths := []struct{ name, path string }{
		{name: "subfinder", path: a.cfg.External.SubfinderBin},
		{name: "dnsx", path: a.cfg.External.DnsxBin},
		{name: "alterx", path: a.cfg.External.AlterxBin},
	}
	missing := make([]string, 0, len(paths))
	for _, item := range paths {
		if strings.TrimSpace(item.path) == "" {
			missing = append(missing, item.name)
		}
	}
	if len(missing) > 0 {
		g.State = GateRefused
		g.Reasons = append(g.Reasons, fmt.Sprintf("pinned backend paths are missing for: %s; set %s, %s and %s", strings.Join(missing, ", "), EnvSubfinderBin, EnvDnsxBin, EnvAlterxBin))
		return g
	}
	g.BinariesConfigured = true
	for _, item := range paths {
		if _, _, err := a.verifyPinnedBinary(item.name, item.path); err != nil {
			g.State = GateUnverified
			g.Reasons = append(g.Reasons, err.Error())
		}
	}
	if g.State == GateUnverified {
		return g
	}
	g.BinariesVerified = true
	g.Pinned = true
	g.State = GateReady
	g.Reasons = append(g.Reasons, "all binaries match the compiled release hashes; no binary version check, download or upgrade is performed at runtime")
	if !g.LiveEnabled {
		g.Reasons = append(g.Reasons, fmt.Sprintf("network-capable discovery and DNS tools remain disabled; set %s=1 only after written program-policy clearance", EnvLiveEnable))
	}
	return g
}
