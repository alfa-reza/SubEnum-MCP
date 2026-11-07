package server

import (
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

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
	fixture            bool
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
		p := filepath.Join(a.cfg.Backend.ManagedBinDir, name)
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
		return ""
	}
	return []struct{ name, path string }{
		{name: "subfinder", path: resolve("subfinder", a.cfg.Backend.SubfinderBin)},
		{name: "dnsx", path: resolve("dnsx", a.cfg.Backend.DnsxBin)},
		{name: "alterx", path: resolve("alterx", a.cfg.Backend.AlterxBin)},
	}
}

// builderPath returns the path to hand to the command builder: an explicit
// env override wins, otherwise the managed path. Binary integrity is
// verified before any execution.
func (a *App) builderPath(name, configured string) string {
	if strings.TrimSpace(configured) != "" {
		return configured
	}
	return filepath.Join(a.cfg.Backend.ManagedBinDir, name)
}

func (a *App) fixtureMode() bool {
	a.pinMu.RLock()
	defer a.pinMu.RUnlock()
	if a.pinned {
		return a.fixture
	}
	return a.cfg.Fixture
}

// verifyRealBackends checks that every pinned backend binary is present and
// matches its compiled release hash. It does not execute binaries or touch the
// network.
func (a *App) verifyRealBackends() error {
	paths := a.binPaths()
	missing := make([]string, 0, len(paths))
	for _, item := range paths {
		if strings.TrimSpace(item.path) == "" {
			missing = append(missing, item.name)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("required backend binary not found: %s; install the hash-pinned releases into %s or set %s, %s and %s", strings.Join(missing, ", "), a.cfg.Backend.ManagedBinDir, EnvSubfinderBin, EnvDnsxBin, EnvAlterxBin)
	}
	var bad []string
	for _, item := range paths {
		if _, _, err := a.verifyPinnedBinary(item.name, item.path); err != nil {
			bad = append(bad, err.Error())
		}
	}
	if len(bad) > 0 {
		return fmt.Errorf("backend binary verification failed: %s", strings.Join(bad, "; "))
	}
	return nil
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
// When fixture is true, the server uses in-process, clearly labeled test
// backends and may accept reserved placeholder roots.
func (a *App) pinScope(root string, fixture bool) error {
	trimmed := strings.TrimSpace(root)
	if trimmed == "" {
		a.pinMu.RLock()
		if a.pinned {
			a.pinMu.RUnlock()
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
	if !fixture && scope.IsReservedPlaceholder(sc.Root()) {
		return fmt.Errorf("scope root %q is a reserved placeholder name; real enumeration refuses placeholders such as %s (use fixture mode only for explicit, labeled tests)", sc.Root(), DefaultRoot)
	}
	dataDir := a.cfg.DataDir
	if a.cfg.ScopeDataDir {
		dataDir = filepath.Join(dataDir, sc.Root())
	}
	st, err := store.Open(dataDir, sc.Root())
	if err != nil {
		return err
	}
	src := mock.New(sc.Root())
	builder := adapters.NewBuilder(sc.Root(),
		a.builderPath("subfinder", a.cfg.Backend.SubfinderBin),
		a.builderPath("dnsx", a.cfg.Backend.DnsxBin),
		a.builderPath("alterx", a.cfg.Backend.AlterxBin),
	).WithDnsxResolvers(a.cfg.Backend.DnsxResolvers)
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
	a.fixture = fixture
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
		if err := app.pinScope(root, cfg.Fixture); err != nil {
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
func (a *App) DataDir() string {
	if root, ok := a.pinnedRoot(); ok && a.cfg.ScopeDataDir {
		return filepath.Join(a.cfg.DataDir, root)
	}
	return a.cfg.DataDir
}

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

// BackendInfos reports backend state. In fixture mode, mock backends are
// ready and real backends are not used. In real mode, binaries are verified
// read-only (no execution) and reported honestly.
func (a *App) BackendInfos() []backend.Info {
	if a.fixtureMode() {
		note := "active: in-process deterministic fixture backend (test mode), no subprocess and no network"
		return []backend.Info{
			{Name: "mock.subfinder", Kind: backend.KindPassive, State: backend.StateReadyFixture, Notes: note},
			{Name: "mock.alterx", Kind: backend.KindCandidates, State: backend.StateReadyFixture, Notes: note},
			{Name: "mock.dnsx", Kind: backend.KindResolver, State: backend.StateReadyFixture, Notes: note},
			{Name: "subfinder", Kind: backend.KindPassive, State: backend.StateDisabled, Notes: "not used in fixture mode"},
			{Name: "dnsx", Kind: backend.KindResolver, State: backend.StateDisabled, Notes: "not used in fixture mode"},
			{Name: "dnsx", Kind: backend.KindBruteforce, State: backend.StateDisabled, Notes: "not used in fixture mode"},
			{Name: "alterx", Kind: backend.KindCandidates, State: backend.StateDisabled, Notes: "not used in fixture mode"},
		}
	}
	bins := map[string]string{}
	for _, b := range a.binPaths() {
		bins[b.name] = b.path
	}
	makeInfo := func(name, kind string) backend.Info {
		var pin adapters.PinnedTool
		for _, candidate := range adapters.PinnedTools() {
			if candidate.Name == name {
				pin = candidate
				break
			}
		}
		path := bins[name]
		info := backend.Info{
			Name: name, Kind: kind, State: backend.StateReady,
			Version: pin.Version, License: pin.License, LicenseVerified: pin.License != "",
			BinaryConfigured: strings.TrimSpace(path) != "",
			Notes:            "real backend; binary integrity verified against compiled release hash before execution",
		}
		if strings.TrimSpace(path) == "" {
			info.State = backend.StateUnverified
			info.Notes = fmt.Sprintf("binary not found; install the hash-pinned release into %s or set the corresponding %s/%s/%s env var", a.cfg.Backend.ManagedBinDir, EnvSubfinderBin, EnvDnsxBin, EnvAlterxBin)
			return info
		}
		_, _, err := a.verifyPinnedBinary(name, path)
		info.BinaryVerified = err == nil
		info.VersionVerified = err == nil
		if err != nil {
			info.State = backend.StateUnverified
			info.Notes = err.Error()
		}
		return info
	}
	return []backend.Info{
		makeInfo("subfinder", backend.KindPassive),
		makeInfo("alterx", backend.KindCandidates),
		makeInfo("dnsx", backend.KindResolver),
		makeInfo("dnsx", backend.KindBruteforce),
	}
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

// Doctor performs local diagnostics. It never executes enumeration binaries
// and never sends network traffic; its writeability check uses and removes a
// unique temp file through the opened managed data root.
func (a *App) Doctor() ([]DoctorCheck, error) {
	root, pinned := a.pinnedRoot()
	checks := []DoctorCheck{}
	scopeCheck := DoctorCheck{
		Name: "scope_root", State: CheckWarn,
		Detail: fmt.Sprintf("scope is not pinned yet; call start_run with scope_root (a registrable domain, e.g. \"bmkg.go.id\") to bind this process, or pre-pin with %s; apex is never in scope", EnvScopeRoot),
	}
	if pinned {
		mode := "real backends"
		if a.fixtureMode() {
			mode = "fixture/test mode (in-process, clearly labeled)"
		}
		scopeCheck = DoctorCheck{
			Name: "scope_root", State: CheckOK,
			Detail: fmt.Sprintf("root %q pinned (%s); the apex is excluded, only subdomains are in scope", root, mode),
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

	if a.fixtureMode() {
		checks = append(checks, DoctorCheck{
			Name: "backends", State: CheckOK,
			Detail: "fixture/test mode active; mock.subfinder, mock.alterx and mock.dnsx run in-process with no network; output is clearly labeled as fixture data",
		})
	} else {
		state := CheckOK
		detail := "real backends ready; binaries match compiled release hashes (verified read-only, not executed)"
		if pinned {
			if err := a.verifyRealBackends(); err != nil {
				state = CheckWarn
				detail = err.Error()
			}
		} else {
			state = CheckWarn
			detail = "scope not pinned; binaries will be verified before execution. " + detail
		}
		checks = append(checks, DoctorCheck{Name: "backends", State: state, Detail: detail})
	}
	checks = append(checks, DoctorCheck{
		Name: "traffic", State: CheckOK,
		Detail: "v1.0.0 performs name enumeration only; no HTTP/HTTPS/TLS, ports, crawling, takeover checks, AXFR, reverse DNS, DNSSEC walking or monitoring",
	})
	return checks, nil
}
