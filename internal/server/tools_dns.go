package server

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/store"
)

// ---- bruteforce_subdomains ----

type BruteforceIn struct {
	RunID          string `json:"run_id,omitempty" jsonschema:"run to append to; empty uses the latest run"`
	Wordlist       string `json:"wordlist,omitempty" jsonschema:"registered preset name; preset-small is the only preset, and empty selects it"`
	MaxWords       *int   `json:"max_words,omitempty" jsonschema:"optional positive cap on words checked, 1–1000"`
	TimeoutSeconds *int   `json:"timeout_seconds,omitempty" jsonschema:"0 or omitted uses the 120-second default; otherwise 1–300 seconds"`
}

type BruteforceOut struct {
	RunID        string          `json:"run_id" jsonschema:"run identifier receiving the results"`
	Root         string          `json:"root" jsonschema:"configured scope root"`
	Mode         string          `json:"mode" jsonschema:"fixture or explicitly enabled external mode"`
	Fixture      bool            `json:"fixture" jsonschema:"whether outputs are synthetic fixture data"`
	Wordlist     string          `json:"wordlist" jsonschema:"registered preset used for this call"`
	WordsQueried int             `json:"words_queried" jsonschema:"number of preset words processed, bounded by max_words"`
	StatusCounts map[string]int  `json:"status_counts" jsonschema:"result counts grouped by DNS status"`
	Records      []*model.Record `json:"records" jsonschema:"stored in-scope records produced by the preset check"`
	Backend      backend.Info    `json:"backend" jsonschema:"backend state and execution provenance"`
}

func (a *App) handleBruteforce(ctx context.Context, req *mcp.CallToolRequest, in BruteforceIn) (result *mcp.CallToolResult, output BruteforceOut, retErr error) {
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if err := a.validateRunForWrite(in.RunID); err != nil {
		return nil, BruteforceOut{}, err
	}
	preset := strings.TrimSpace(in.Wordlist)
	if preset == "" {
		preset = "preset-small"
	}
	if _, ok := presetWordlists[preset]; !ok {
		return nil, BruteforceOut{}, fmt.Errorf("unknown wordlist preset %q; only registered presets are accepted in v1.0.0: %s (arbitrary paths and custom lists are rejected)", preset, presetNames())
	}
	maxWords, err := clampCap(in.MaxWords, CapMaxBruteforceWords, CapMaxBruteforceWords, "max_words")
	if err != nil {
		return nil, BruteforceOut{}, err
	}
	timeout, err := timeoutForTool(in.TimeoutSeconds)
	if err != nil {
		return nil, BruteforceOut{}, err
	}
	if a.cfg.External.Requested {
		if err := a.requireExternal(true); err != nil {
			return nil, BruteforceOut{}, err
		}
	}
	wordlistPath := ""
	if a.cfg.External.Requested {
		wordlistPath, err = a.MaterializePreset(preset, maxWords)
		if err != nil {
			return nil, BruteforceOut{}, err
		}
		defer func() {
			if cleanupErr := a.store.RemoveWorkFile(wordlistPath); cleanupErr != nil {
				if retErr == nil {
					retErr = fmt.Errorf("remove managed temporary wordlist: %w", cleanupErr)
				} else {
					retErr = fmt.Errorf("%w (remove managed temporary wordlist: %v)", retErr, cleanupErr)
				}
			}
		}()
	}
	run, err := a.runForWrite(in.RunID)
	if err != nil {
		return nil, BruteforceOut{}, err
	}
	if err := run.CheckMode(!a.cfg.External.Requested); err != nil {
		return nil, BruteforceOut{}, err
	}
	mode, fixture := fixtureMode, true
	backendInfo := a.fixtureBackendInfo("mock.dnsx", backend.KindBruteforce)
	var records []*model.Record
	if a.cfg.External.Requested {
		records, err = a.external.Bruteforce(ctx, backend.BruteforceRequest{
			RunID: run.ID, Root: a.Root(), Preset: preset, MaxWords: maxWords,
			Words: presetWords(preset), WordlistPath: wordlistPath, Timeout: timeout,
		})
		mode, fixture = externalMode, false
		backendInfo = a.externalBackendInfo("dnsx", backend.KindBruteforce)
	} else {
		records, err = a.brute.Bruteforce(ctx, backend.BruteforceRequest{RunID: run.ID, Root: a.Root(), Preset: preset, MaxWords: maxWords, Timeout: timeout})
	}
	if err != nil {
		return nil, BruteforceOut{}, err
	}
	stored, err := a.upsertAll(run, records)
	if err != nil {
		return nil, BruteforceOut{}, err
	}
	return nil, BruteforceOut{
		RunID:        run.ID,
		Root:         a.Root(),
		Mode:         mode,
		Fixture:      fixture,
		Wordlist:     preset,
		WordsQueried: len(stored),
		StatusCounts: statusCounts(stored),
		Records:      sampleRecords(stored),
		Backend:      backendInfo,
	}, nil
}

// ---- resolve_hosts ----

type ResolveIn struct {
	RunID          string   `json:"run_id,omitempty" jsonschema:"run to append to; empty uses the latest run"`
	Hosts          []string `json:"hosts,omitempty" jsonschema:"up to 2000 input hostnames; empty resolves hosts already stored in the run"`
	MaxHosts       *int     `json:"max_hosts,omitempty" jsonschema:"optional positive cap on in-scope hosts resolved per call, 1–2000"`
	HostOffset     *int     `json:"host_offset,omitempty" jsonschema:"0-based offset over stored in-scope hosts when hosts is omitted; minimum 0"`
	HostLimit      *int     `json:"host_limit,omitempty" jsonschema:"batch size over stored in-scope hosts when hosts is omitted, 1–2000; defaults to max_hosts"`
	TimeoutSeconds *int     `json:"timeout_seconds,omitempty" jsonschema:"0 or omitted uses the 120-second default; otherwise 1–300 seconds"`
}

type ResolveOut struct {
	RunID          string          `json:"run_id" jsonschema:"run identifier receiving the results"`
	Root           string          `json:"root" jsonschema:"configured scope root"`
	Mode           string          `json:"mode" jsonschema:"fixture or explicitly enabled external mode"`
	Fixture        bool            `json:"fixture" jsonschema:"whether outputs are synthetic fixture data"`
	Requested      int             `json:"requested" jsonschema:"number of hostnames supplied or selected from the run for this call"`
	Accepted       int             `json:"accepted" jsonschema:"unique in-scope subdomains sent to a resolver"`
	Dropped        []DroppedInput  `json:"dropped" jsonschema:"out-of-scope or malformed inputs rejected before any backend call"`
	StatusCounts   map[string]int  `json:"status_counts" jsonschema:"accepted result counts grouped by DNS status"`
	Records        []*model.Record `json:"records" jsonschema:"stored in-scope resolution records"`
	Backend        backend.Info    `json:"backend" jsonschema:"backend state and execution provenance"`
	HostTotal      int             `json:"host_total,omitempty" jsonschema:"total stored in-scope hosts in the run when hosts is omitted"`
	HostOffset     int             `json:"host_offset,omitempty" jsonschema:"offset used over stored in-scope hosts when hosts is omitted"`
	HostBatch      int             `json:"host_batch,omitempty" jsonschema:"stored in-scope hosts selected for this call when hosts is omitted"`
	HostNextOffset *int            `json:"host_next_offset,omitempty" jsonschema:"next offset over stored in-scope hosts, or null when no hosts remain"`
}

func (a *App) handleResolve(ctx context.Context, req *mcp.CallToolRequest, in ResolveIn) (*mcp.CallToolResult, ResolveOut, error) {
	a.operationMu.Lock()
	defer a.operationMu.Unlock()
	if err := a.validateRunForWrite(in.RunID); err != nil {
		return nil, ResolveOut{}, err
	}
	maxHosts, err := clampCap(in.MaxHosts, CapMaxResolveHosts, CapMaxResolveHosts, "max_hosts")
	if err != nil {
		return nil, ResolveOut{}, err
	}
	timeout, err := timeoutForTool(in.TimeoutSeconds)
	if err != nil {
		return nil, ResolveOut{}, err
	}
	if len(in.Hosts) > CapMaxResolveHosts {
		return nil, ResolveOut{}, fmt.Errorf("hosts list has %d entries; the server hard cap is %d per call; split the request", len(in.Hosts), CapMaxResolveHosts)
	}
	mode, fixture := fixtureMode, true
	if a.cfg.External.Requested {
		mode, fixture = externalMode, false
	}
	out := ResolveOut{Root: a.Root(), Mode: mode, Fixture: fixture, Dropped: []DroppedInput{}}

	var hosts []string
	var run *store.Run
	if len(in.Hosts) == 0 {
		run, err = a.runForRead(in.RunID)
		if err != nil {
			return nil, ResolveOut{}, err
		}
		hostOffset := 0
		if in.HostOffset != nil {
			if *in.HostOffset < 0 {
				return nil, ResolveOut{}, fmt.Errorf("host_offset must be 0 or greater; got %d", *in.HostOffset)
			}
			hostOffset = *in.HostOffset
		}
		hostLimit := maxHosts
		if in.HostLimit != nil {
			if *in.HostLimit <= 0 || *in.HostLimit > CapMaxResolveHosts {
				return nil, ResolveOut{}, fmt.Errorf("host_limit must be between 1 and %d; got %d", CapMaxResolveHosts, *in.HostLimit)
			}
			hostLimit = *in.HostLimit
		}
		allHosts := hostnames(run.InScope(""))
		out.HostTotal = len(allHosts)
		out.HostOffset = hostOffset
		if hostOffset > len(allHosts) {
			hostOffset = len(allHosts)
			out.HostOffset = hostOffset
		}
		end := hostOffset + hostLimit
		if end > len(allHosts) {
			end = len(allHosts)
		}
		hosts = allHosts[hostOffset:end]
		out.HostBatch = len(hosts)
		if end < len(allHosts) {
			next := end
			out.HostNextOffset = &next
		}
		out.Requested = len(hosts)
		if len(hosts) > maxHosts {
			return nil, ResolveOut{}, fmt.Errorf("%d stored hosts selected exceeds max_hosts cap of %d; lower host_limit/max_hosts", len(hosts), maxHosts)
		}
	} else {
		out.Requested = len(in.Hosts)
		seen := map[string]bool{}
		for _, raw := range in.Hosts {
			cls := a.scope.Classify(raw)
			if cls.InScope {
				if !seen[cls.Normalized] {
					seen[cls.Normalized] = true
					hosts = append(hosts, cls.Normalized)
				}
				continue
			}
			out.Dropped = append(out.Dropped, DroppedInput{Input: raw, Host: cls.Normalized, Reason: cls.Reason})
		}
		if len(hosts) > maxHosts {
			return nil, ResolveOut{}, fmt.Errorf("%d in-scope hosts accepted exceeds the max_hosts cap of %d; raise max_hosts within the server hard cap or split the request", len(hosts), maxHosts)
		}
	}
	if a.cfg.External.Requested && len(hosts) > 0 {
		if err := a.requireExternal(true); err != nil {
			return nil, ResolveOut{}, err
		}
	}
	if run == nil {
		if len(hosts) == 0 {
			run, err = a.runForRead(in.RunID)
			if err != nil {
				return nil, ResolveOut{}, fmt.Errorf("no in-scope hosts remain and no existing run is available; refusing to create a run: %w", err)
			}
		} else {
			run, err = a.runForWrite(in.RunID)
		}
		if err != nil {
			return nil, ResolveOut{}, err
		}
	}
	out.RunID = run.ID
	if err := run.CheckMode(!a.cfg.External.Requested); err != nil {
		return nil, ResolveOut{}, err
	}
	out.Accepted = len(hosts)

	if len(hosts) > 0 {
		var records []*model.Record
		if a.cfg.External.Requested {
			records, err = a.external.Resolve(ctx, backend.ResolveRequest{RunID: run.ID, Root: a.Root(), Hosts: hosts, MaxHosts: maxHosts, Timeout: timeout})
		} else {
			records, err = a.res.Resolve(ctx, backend.ResolveRequest{RunID: run.ID, Root: a.Root(), Hosts: hosts, MaxHosts: maxHosts, Timeout: timeout})
		}
		if err != nil {
			return nil, ResolveOut{}, err
		}
		stored, err := a.upsertAll(run, records)
		if err != nil {
			return nil, ResolveOut{}, err
		}
		out.Records = sampleRecords(stored)
		out.StatusCounts = statusCounts(stored)
	} else {
		out.Records = []*model.Record{}
		out.StatusCounts = map[string]int{}
	}
	for _, dropped := range out.Dropped {
		host := dropped.Host
		if host == "" {
			host = sanitizeDroppedHost(dropped.Input)
		}
		if _, err := run.Upsert(&model.Record{
			RunID:      run.ID,
			Host:       host,
			Status:     model.StatusCandidate,
			Provenance: []model.Provenance{{Backend: "intake", Method: "resolve", Detail: "rejected at intake; no backend call", Fixture: !a.cfg.External.Requested}},
			ObservedAt: time.Now().UTC(),
			InScope:    false,
			DropReason: dropped.Reason,
			Notes:      "rejected at intake before any backend call; excluded from pagination and export",
		}); err != nil {
			return nil, ResolveOut{}, err
		}
	}
	if a.cfg.External.Requested {
		out.Backend = a.externalBackendInfo("dnsx", backend.KindResolver)
	} else {
		out.Backend = a.fixtureBackendInfo("mock.dnsx", backend.KindResolver)
	}
	return nil, out, nil
}

// sanitizeDroppedHost keeps stored rejection entries single-line and short.
func sanitizeDroppedHost(raw string) string {
	h := strings.ToLower(strings.TrimSpace(raw))
	h = strings.ReplaceAll(h, "/", "_")
	h = strings.ReplaceAll(h, "\\", "_")
	if len(h) > 100 {
		h = h[:100]
	}
	if h == "" {
		h = "(empty-input)"
	}
	return h
}
