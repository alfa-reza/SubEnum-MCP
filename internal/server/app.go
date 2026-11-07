package server

import (
	"context"
	"fmt"
	"log/slog"
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

func NewApp(cfg *Config, logger *slog.Logger) (*App, error) {
	sc, err := scope.New(cfg.ScopeRoot, scope.DefaultPolicy())
	if err != nil {
		return nil, fmt.Errorf("invalid %s: %w", EnvScopeRoot, err)
	}
	st, err := store.Open(cfg.DataDir, sc.Root())
	if err != nil {
		return nil, err
	}
	src := mock.New(sc.Root())
	builder := adapters.NewBuilder(sc.Root(), cfg.External.SubfinderBin, cfg.External.DnsxBin, cfg.External.AlterxBin)
	runner := adapters.ExecRunner{}
	external, err := adapters.NewExternalBackends(sc, builder, runner)
	if err != nil {
		return nil, err
	}
	return &App{
		cfg:                cfg,
		scope:              sc,
		store:              st,
		mock:               src,
		log:                logger,
		disc:               &mock.Discoverer{Src: src},
		gen:                &mock.Generator{Src: src},
		brute:              &mock.Bruteforcer{Src: src},
		res:                &mock.Resolver{Src: src},
		builder:            builder,
		runner:             runner,
		external:           external,
		verifyPinnedBinary: adapters.VerifyPinnedBinary,
	}, nil
}

func (a *App) Root() string        { return a.scope.Root() }
func (a *App) DataDir() string     { return a.store.Dir() }
func (a *App) Store() *store.Store { return a.store }

// MaterializePreset writes a bounded registered preset into the managed work
// folder (only ever called on the external path) and returns the file path.
func (a *App) MaterializePreset(name string, maxWords int) (string, error) {
	if _, ok := presetWordlists[name]; !ok {
		return "", fmt.Errorf("unknown wordlist preset %q; registered presets: %s", name, presetNames())
	}
	if maxWords < 1 || maxWords > CapMaxBruteforceWords {
		return "", fmt.Errorf("max_words must be between 1 and %d", CapMaxBruteforceWords)
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
	switch g.State {
	case GateRefused:
		extNote = strings.Join(g.Reasons, "; ")
	case GateUnverified:
		extState = backend.StateUnverified
		extNote = strings.Join(g.Reasons, "; ")
	case GateReady:
		extState = backend.StateReady
		extNote = strings.Join(g.Reasons, "; ")
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
	addExternal("subfinder", backend.KindPassive, a.cfg.External.SubfinderBin, true)
	addExternal("dnsx", backend.KindResolver, a.cfg.External.DnsxBin, true)
	addExternal("dnsx", backend.KindBruteforce, a.cfg.External.DnsxBin, true)
	addExternal("alterx", backend.KindCandidates, a.cfg.External.AlterxBin, false)
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
	checks := []DoctorCheck{}
	checks = append(checks, DoctorCheck{
		Name: "scope_root", State: CheckOK,
		Detail: fmt.Sprintf("root %q from %s (default %s); apex is excluded, only subdomains are in scope", a.scope.Root(), EnvScopeRoot, DefaultRoot),
	})
	checks = append(checks, DoctorCheck{
		Name: "scope_policy", State: CheckOK,
		Detail: "lowercase normalization, single trailing dot stripped, DNS label boundaries enforced; Unicode and unvalidated xn-- A-labels are rejected",
	})

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
	if g.Requested && g.State == GateDisabled {
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
