package server

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/adapters"
	"github.com/alfa-reza/SubEnum-MCP/internal/assets"
	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/mock"
	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
	"github.com/alfa-reza/SubEnum-MCP/internal/store"
)

// Preset wordlists registered in code. Tool input may only reference one of
// these names; arbitrary paths are rejected.
var presetWordlists = map[string]string{
	"preset-small": assets.PresetSmall,
}

type App struct {
	operationMu        sync.Mutex
	cfg                *Config
	pinMu              sync.RWMutex
	pinned             bool
	scope              *scope.Scope
	store              *store.Store
	mock               *mock.Source
	log                *slog.Logger
	disc               backend.Discoverer
	gen                backend.CandidateGenerator
	brute              backend.Bruteforcer
	res                backend.Resolver
	builder            *adapters.Builder
	runner             adapters.Runner
	external           *adapters.ExternalBackends
	verifyPinnedBinary func(name, path string) (adapters.PinnedTool, string, error)
}

// pinnedRoot reports the scope this process is bound to, and whether any pin
// exists yet. Pinning happens either eagerly at startup (SUBENUM_SCOPE_ROOT)
// or lazily at the first start_run call.
func (a *App) pinnedRoot() (string, bool) {
	a.pinMu.RLock()
	defer a.pinMu.RUnlock()
	if !a.pinned {
		return "", false
	}
	return a.scope.Root(), true
}

// binPaths resolves the three backend binaries for gate/verification
// purposes. An empty path means the backend is not configured and absent
// from the managed directory; the caller decides how to report that.
func (a *App) binPaths() []struct{ name, path string } {
	resolve := func(name, configured string) string {
		if strings.TrimSpace(configured) != "" {
			return configured
		}
		p := filepath.Join(a.cfg.External.ManagedBinDir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
		return ""
	}
	return []struct{ name, path string }{
		{name: "subfinder", path: resolve("subfinder", a.cfg.External.SubfinderBin)},
		{name: "dnsx", path: resolve("dnsx", a.cfg.External.DnsxBin)},
		{name: "alterx", path: resolve("alterx", a.cfg.External.AlterxBin)},
	}
}

// builderPath returns the path to hand to the command builder: an explicit
// env override wins, otherwise the managed path (verification happens at the
// gate, before any execution).
func (a *App) builderPath(name, configured string) string {
	if strings.TrimSpace(configured) != "" {
		return configured
	}
	return filepath.Join(a.cfg.External.ManagedBinDir, name)
}

// errNotPinned is returned by every tool that needs a scope before the
// process has been pinned by start_run.
var errNotPinned = errors.New("scope is not pinned; call start_run with scope_root (a registrable domain, e.g. \"bmkg.go.id\") first")

func (a *App) ensurePinned() error {
	if _, ok := a.pinnedRoot(); !ok {
		return errNotPinned
	}
	return nil
}

// pinScope validates root and binds this process to it. An already-pinned
// process accepts a repeat call with the same root and rejects any change.
func (a *App) pinScope(root string) error {
	trimmed := strings.TrimSpace(root)
	if trimmed == "" {
		a.pinMu.RLock()
		if a.pinned {
			a.pinMu.RUnlock()
			// Already pinned (for example via SUBENUM_SCOPE_ROOT): a bare
			// call to start_run reuses the existing pin.
			return nil
		}
		a.pinMu.RUnlock()
		return fmt.Errorf("scope_root is required; provide the registrable domain you are authorized to enumerate (for example \"bmkg.go.id\")")
	}
	a.pinMu.Lock()
	defer a.pinMu.Unlock()
	if a.pinned {
		want := strings.ToLower(strings.TrimSuffix(trimmed, "."))
		if a.scope.Root() == want {
			return nil
		}
		return fmt.Errorf("this subenum-mcp process is pinned to scope %q; it cannot switch to %q; restart the server for a different target", a.scope.Root(), trimmed)
	}
	sc, err := scope.New(trimmed, scope.DefaultPolicy())
	if err != nil {
		return fmt.Errorf("invalid scope_root %q: %w", trimmed, err)
	}
	st, err := store.Open(a.cfg.DataDir, sc.Root())
	if err != nil {
		return err
	}
	src := mock.New(sc.Root())
	builder := adapters.NewBuilder(sc.Root(),
		a.builderPath("subfinder", a.cfg.External.SubfinderBin),
		a.builderPath("dnsx", a.cfg.External.DnsxBin),
		a.builderPath("alterx", a.cfg.External.AlterxBin),
	).WithDnsxResolvers(a.cfg.External.DnsxResolvers)
	external, err := adapters.NewExternalBackends(sc, builder, a.runner)
	if err != nil {
		_ = st.Close()
		return err
	}
	a.scope = sc
	a.store = st
	a.mock = src
	a.disc = &mock.Discoverer{Src: src}
	a.gen = &mock.Generator{Src: src}
	a.brute = &mock.Bruteforcer{Src: src}
	a.res = &mock.Resolver{Src: src}
	a.builder = builder
	a.external = external
	a.pinned = true
	return nil
}

func NewApp(cfg *Config, logger *slog.Logger) (*App, error) {
	app := &App{
		cfg:                cfg,
		log:                logger,
		runner:             adapters.ExecRunner{},
		verifyPinnedBinary: adapters.VerifyPinnedBinary,
	}
	if root := strings.TrimSpace(cfg.ScopeRoot); root != "" {
		if err := app.pinScope(root); err != nil {
			return nil, fmt.Errorf("invalid %s: %w", EnvScopeRoot, err)
		}
	}
	return app, nil
}

// Root returns the pinned scope root, or "" when the process is not pinned
// yet. Prefer ensurePinned before reading run data.
func (a *App) Root() string {
	root, _ := a.pinnedRoot()
	return root
}
func (a *App) DataDir() string { return a.cfg.DataDir }

// Store returns the managed store once pinned, or nil beforehand.
func (a *App) Store() *store.Store { return a.store }

// Close releases the managed store if it was opened.
func (a *App) Close() error {
	if a.store == nil {
		return nil
	}
	return a.store.Close()
}

// MaterializePreset writes a bounded registered preset into the managed work
// folder (only ever called on the external path) and returns the file path.
func (a *App) MaterializePreset(name string, maxWords int) (string, error) {
	if _, ok := presetWordlists[name]; !ok {
		return "", fmt.Errorf("unknown wordlist preset %q; registered presets: %s", name, presetNames())
	}
	if maxWords < 1 || maxWords > CapMaxBruteforceWords {
		return "", fmt.Errorf("max_words must be between 1 and %d", CapMaxBruteforceWords)
	}
	if a.store == nil {
		return "", errNotPinned
	}
	words := presetWords(name)
	if len(words) > maxWords {
		words = words[:maxWords]
	}
	return a.store.MaterializeWorkFile("wordlist-"+name+".txt", []byte(strings.Join(words, "\n")+"\n"))
}

func presetNames() string {
	names := make([]string, 0, len(presetWordlists))
	for n := range presetWordlists {
		names = append(names, n)
	}
	sort.Strings(names)
	return strings.Join(names, ", ")
}

func parseExternalHosts(stdout []byte, configuredScope *scope.Scope) ([]string, error) {
	return adapters.ParseExternalNames(stdout, configuredScope)
}

// BackendInfos reports fixture readiness and pinned release state without
// launching any executable. Network backends remain disabled unless the
// separate live gate is explicitly enabled.
func (a *App) BackendInfos() []backend.Info {
	g := a.externalGate()

	fixtureNote := "offline deterministic fixture backend; runs in-process, no subprocess and no network"
	extState := backend.StateDisabled
	extNote := "external mode disabled; fixture backends are the default"
	if len(g.Reasons) > 0 {
		extNote = strings.Join(g.Reasons, "; ")
	}
	switch g.State {
	case GateRefused:
	case GateUnverified:
		extState = backend.StateUnverified
	case GateReady:
		extState = backend.StateReady
	}
	infos := []backend.Info{
		{Name: "mock.subfinder", Kind: backend.KindPassive, State: backend.StateReadyFixture, Notes: fixtureNote},
		{Name: "mock.alterx", Kind: backend.KindCandidates, State: backend.StateReadyFixture, Notes: fixtureNote},
		{Name: "mock.dnsx", Kind: backend.KindResolver, State: backend.StateReadyFixture, Notes: fixtureNote},
	}
	addExternal := func(name, kind, path string, needsLive bool) {
		state, note := extState, extNote
		if needsLive && g.State == GateReady && !g.LiveEnabled {
			state = backend.StateDisabled
			note += "; live discovery/DNS is blocked until the separate live opt-in is enabled"
		}
		var pin adapters.PinnedTool
		for _, candidate := range adapters.PinnedTools() {
			if candidate.Name == name {
				pin = candidate
				break
			}
		}
		info := backend.Info{
			Name: name, Kind: kind, State: state, Version: pin.Version,
			License: pin.License, LicenseVerified: pin.License != "",
			BinaryConfigured: strings.TrimSpace(path) != "", Notes: note,
		}
		if path != "" {
			_, _, err := a.verifyPinnedBinary(name, path)
			info.BinaryVerified = err == nil
			info.VersionVerified = err == nil
			if err != nil && g.State == GateUnverified {
				info.Notes += "; " + err.Error()
			}
		}
		infos = append(infos, info)
	}
	bins := map[string]string{}
	for _, b := range a.binPaths() {
		bins[b.name] = b.path
	}
	addExternal("subfinder", backend.KindPassive, bins["subfinder"], true)
	addExternal("dnsx", backend.KindResolver, bins["dnsx"], true)
	addExternal("dnsx", backend.KindBruteforce, bins["dnsx"], true)
	addExternal("alterx", backend.KindCandidates, bins["alterx"], false)
	return infos
}

// DoctorCheck is one diagnostic line.
type DoctorCheck struct {
	Name   string `json:"name"`
	State  string `json:"state"`
	Detail string `json:"detail"`
}

const (
	CheckOK   = "ok"
	CheckWarn = "warn"
	CheckFail = "fail"
)

// Doctor performs local diagnostics. It never launches external binaries and
// never sends traffic; its writeability check uses and removes a unique temp file.
func (a *App) Doctor() ([]DoctorCheck, error) {
	root, pinned := a.pinnedRoot()
	checks := []DoctorCheck{}
	scopeCheck := DoctorCheck{
		Name: "scope_root", State: CheckWarn,
		Detail: fmt.Sprintf("scope is not pinned yet; call start_run with scope_root (a registrable domain, e.g. \"bmkg.go.id\") to bind this process, or pre-pin with %s; apex is never in scope", EnvScopeRoot),
	}
	if pinned {
		scopeCheck = DoctorCheck{
			Name: "scope_root", State: CheckOK,
			Detail: fmt.Sprintf("root %q pinned by this process; the apex is excluded, only subdomains are in scope", root),
		}
	}
	checks = append(checks, scopeCheck)
	checks = append(checks, DoctorCheck{
		Name: "scope_policy", State: CheckOK,
		Detail: "lowercase normalization, single trailing dot stripped, DNS label boundaries enforced; Unicode and unvalidated xn-- A-labels are rejected",
	})

	if a.store != nil {
		probeErr := a.store.ProbeWrite()
		writable := probeErr == nil
		state := CheckOK
		if !writable {
			state = CheckFail
		}
		dataDirDetail := fmt.Sprintf("managed data dir %s (writable: %t; rooted temporary probe is removed)", a.store.Dir(), writable)
		if probeErr != nil {
			dataDirDetail += "; write probe failed: " + probeErr.Error()
		}
		checks = append(checks, DoctorCheck{Name: "data_dir", State: state, Detail: dataDirDetail})
		runs := a.store.Runs()
		recs := 0
		dropped := 0
		for _, r := range runs {
			recs += r.Count()
			dropped += len(r.Dropped())
		}
		checks = append(checks, DoctorCheck{Name: "runs", State: CheckOK, Detail: fmt.Sprintf("%d runs, %d records (%d rejected-at-intake entries with drop reasons)", len(runs), recs, dropped)})
	} else {
		checks = append(checks, DoctorCheck{
			Name: "data_dir", State: CheckWarn,
			Detail: fmt.Sprintf("managed data dir %s (not bound yet; it is opened, permission-restricted and scope-matched at the first start_run; writability will be probed then)", a.cfg.DataDir),
		})
		checks = append(checks, DoctorCheck{Name: "runs", State: CheckOK, Detail: "no runs loaded; the data dir is bound to the pinned root at the first start_run"})
	}

	checks = append(checks, DoctorCheck{
		Name: "fixture_backends", State: CheckOK,
		Detail: "mock.subfinder, mock.alterx and mock.dnsx are ready; output is always labeled as fixture data",
	})

	g := a.externalGate()
	st := CheckOK
	switch g.State {
	case GateRefused:
		st = CheckFail
	case GateUnverified:
		st = CheckWarn
	}
	if !pinned {
		st = CheckWarn
	} else if g.Requested && g.State == GateDisabled {
		st = CheckFail
	}
	if g.State == GateReady && !g.LiveEnabled {
		st = CheckWarn
	}
	checks = append(checks, DoctorCheck{
		Name: "external_gate", State: st,
		Detail: fmt.Sprintf("state %q; %s", g.State, strings.Join(g.Reasons, "; ")),
	})
	checks = append(checks, DoctorCheck{
		Name: "traffic", State: CheckOK,
		Detail: "v1.0.0 performs name enumeration only; no HTTP/HTTPS/TLS, ports, crawling, takeover checks, AXFR, reverse DNS, DNSSEC walking or monitoring",
	})
	return checks, nil
}

func (a *App) requireExternal(networkRequired bool) error {
	g := a.externalGate()
	if g.State != GateReady {
		return fmt.Errorf("external backend gate is %s: %s", g.State, strings.Join(g.Reasons, "; "))
	}
	if networkRequired && !g.LiveEnabled {
		return fmt.Errorf("live network backend is disabled; %s=1 is required only after written program-policy clearance", EnvLiveEnable)
	}
	return nil
}

// externalDiscover is a small test hook retained for backwards compatibility;
// normal MCP calls use the typed adapter directly and the same gates.
func (a *App) externalDiscover(ctx context.Context) ([]string, error) {
	if err := a.requireExternal(true); err != nil {
		return nil, err
	}
	records, err := a.external.Discover(ctx, backend.DiscoverRequest{
		RunID: "diagnostic", Root: a.Root(), MaxRecords: CapMaxRecordsPerCall,
		Timeout: time.Duration(DefaultTimeoutSeconds) * time.Second,
	})
	if err != nil {
		return nil, err
	}
	return hostnames(records), nil
}
