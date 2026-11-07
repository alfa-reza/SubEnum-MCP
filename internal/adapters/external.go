package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

const (
	MaxExternalOutputHosts = 5000
	MaxExternalSeedHosts   = 2000
	MaxExternalWords       = 1000
	MaxExternalResolve     = 2000
)

// ExternalBackends adapts the pinned ProjectDiscovery binaries to the typed
// backend interfaces. It never chooses a binary, flag, resolver, or file path
// from MCP tool input; configuration and argv builders are server-owned.
type ExternalBackends struct {
	scope   *scope.Scope
	builder *Builder
	runner  Runner
}

func NewExternalBackends(configuredScope *scope.Scope, builder *Builder, runner Runner) (*ExternalBackends, error) {
	if configuredScope == nil {
		return nil, fmt.Errorf("configured scope is required")
	}
	if builder == nil {
		return nil, fmt.Errorf("external command builder is required")
	}
	if runner == nil {
		return nil, fmt.Errorf("external process runner is required")
	}
	return &ExternalBackends{scope: configuredScope, builder: builder, runner: runner}, nil
}

func (e *ExternalBackends) validateRoot(root string) error {
	norm, err := scope.Normalize(root)
	if err != nil {
		return err
	}
	if norm != e.scope.Root() {
		return fmt.Errorf("request root %q does not match configured scope root", norm)
	}
	if scope.IsReservedPlaceholder(norm) {
		return fmt.Errorf("external backend refuses reserved placeholder scope %q", norm)
	}
	return nil
}

func (e *ExternalBackends) Discover(ctx context.Context, req backend.DiscoverRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.validateRoot(req.Root); err != nil {
		return nil, err
	}
	if req.MaxRecords <= 0 || req.MaxRecords > MaxExternalOutputHosts {
		return nil, fmt.Errorf("max_records must be between 1 and %d", MaxExternalOutputHosts)
	}
	spec, err := e.builder.BuildSubfinderDiscoverBounded(scope.DefaultPolicy(), req.MaxRecords, req.Timeout)
	if err != nil {
		return nil, err
	}
	stdout, _, err := e.runner.Run(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hosts, err := ParseExternalNames(stdout, e.scope)
	if err != nil {
		return nil, err
	}
	if len(hosts) > req.MaxRecords {
		hosts = hosts[:req.MaxRecords]
	}
	records := make([]*model.Record, 0, len(hosts))
	for _, host := range hosts {
		records = append(records, externalRecord(req.RunID, host, model.StatusCandidate, "subfinder", model.MethodPassive, "passive source result; pinned binary output; not independently validated"))
	}
	return records, nil
}

func (e *ExternalBackends) Generate(ctx context.Context, req backend.CandidateRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.validateRoot(req.Root); err != nil {
		return nil, err
	}
	if req.MaxOut <= 0 || req.MaxOut > MaxExternalOutputHosts {
		return nil, fmt.Errorf("max_candidates must be between 1 and %d", MaxExternalOutputHosts)
	}
	if len(req.Seeds) == 0 || len(req.Seeds) > MaxExternalSeedHosts {
		return nil, fmt.Errorf("seed host count must be between 1 and %d", MaxExternalSeedHosts)
	}
	seeds := make([]string, 0, len(req.Seeds))
	seen := map[string]bool{}
	for _, raw := range req.Seeds {
		c := e.scope.Classify(raw)
		if !c.InScope || seen[c.Normalized] {
			continue
		}
		seen[c.Normalized] = true
		seeds = append(seeds, c.Normalized)
	}
	if len(seeds) == 0 {
		return nil, fmt.Errorf("no in-scope seed subdomains remain after scope validation")
	}
	spec, err := e.builder.BuildAlterXCandidatesBounded(seeds, req.MaxOut, req.Timeout)
	if err != nil {
		return nil, err
	}
	stdout, _, err := e.runner.Run(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hosts, err := ParseExternalNames(stdout, e.scope)
	if err != nil {
		return nil, err
	}
	if len(hosts) > req.MaxOut {
		hosts = hosts[:req.MaxOut]
	}
	records := make([]*model.Record, 0, len(hosts))
	for _, host := range hosts {
		records = append(records, externalRecord(req.RunID, host, model.StatusCandidate, "alterx", model.MethodCandidateGen, "candidate generated locally from in-scope seeds; DNS validity not established"))
	}
	return records, nil
}

func (e *ExternalBackends) Bruteforce(ctx context.Context, req backend.BruteforceRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.validateRoot(req.Root); err != nil {
		return nil, err
	}
	if req.Preset != "preset-small" {
		return nil, fmt.Errorf("external dnsx accepts only the registered preset-small wordlist")
	}
	if req.MaxWords <= 0 || req.MaxWords > MaxExternalWords {
		return nil, fmt.Errorf("max_words must be between 1 and %d", MaxExternalWords)
	}
	words := make([]string, 0, len(req.Words))
	seenWords := make(map[string]bool, len(req.Words))
	for _, raw := range req.Words {
		word := strings.ToLower(strings.TrimSpace(raw))
		if word == "" || strings.HasPrefix(word, "#") {
			continue
		}
		if strings.Contains(word, ".") {
			return nil, fmt.Errorf("registered wordlist contains a non-label value")
		}
		if err := scope.ValidateHostname(word, scope.DefaultPolicy()); err != nil {
			return nil, fmt.Errorf("registered wordlist contains an invalid DNS label: %w", err)
		}
		if seenWords[word] {
			continue
		}
		seenWords[word] = true
		words = append(words, word)
		if len(words) >= req.MaxWords {
			break
		}
	}
	if len(words) == 0 {
		return nil, fmt.Errorf("registered wordlist has no usable words")
	}
	if req.WordlistPath == "" {
		return nil, fmt.Errorf("server-managed wordlist path is required")
	}
	spec, err := e.builder.BuildDNSXBruteforceBounded(req.WordlistPath, scope.DefaultPolicy(), len(words), req.Timeout)
	if err != nil {
		return nil, err
	}
	stdout, _, err := e.runner.Run(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolved, err := ParseDNSXNames(stdout, e.scope)
	if err != nil {
		return nil, err
	}
	resolvedSet := make(map[string]bool, len(resolved))
	for _, host := range resolved {
		resolvedSet[host] = true
	}
	records := make([]*model.Record, 0, len(words))
	for _, word := range words {
		host := word + "." + e.scope.Root()
		status, note := model.StatusNoAnswer, model.NoteNoAnswerNotNXDOMAIN
		if resolvedSet[host] {
			status, note = model.StatusResolved, "DNS response observed; response values are not retained by the name-enumeration tool"
		}
		records = append(records, externalRecord(req.RunID, host, status, "dnsx", model.MethodBruteforce, note))
	}
	return records, nil
}

func (e *ExternalBackends) Resolve(ctx context.Context, req backend.ResolveRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if err := e.validateRoot(req.Root); err != nil {
		return nil, err
	}
	if len(req.Hosts) == 0 || len(req.Hosts) > MaxExternalResolve {
		return nil, fmt.Errorf("host count must be between 1 and %d", MaxExternalResolve)
	}
	hosts := make([]string, 0, len(req.Hosts))
	seen := map[string]bool{}
	for _, raw := range req.Hosts {
		c := e.scope.Classify(raw)
		if !c.InScope || seen[c.Normalized] {
			continue
		}
		seen[c.Normalized] = true
		hosts = append(hosts, c.Normalized)
	}
	if len(hosts) == 0 {
		return nil, fmt.Errorf("no in-scope subdomains remain after scope validation")
	}
	spec, err := e.builder.BuildDNSXResolveBounded(hosts, req.MaxHosts, req.Timeout)
	if err != nil {
		return nil, err
	}
	stdout, _, err := e.runner.Run(ctx, spec)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	resolved, err := ParseDNSXNames(stdout, e.scope)
	if err != nil {
		return nil, err
	}
	resolvedSet := make(map[string]bool, len(resolved))
	for _, host := range resolved {
		resolvedSet[host] = true
	}
	records := make([]*model.Record, 0, len(hosts))
	for _, host := range hosts {
		status, note := model.StatusNoAnswer, model.NoteNoAnswerNotNXDOMAIN
		if resolvedSet[host] {
			status, note = model.StatusResolved, "DNS response observed; response values are not retained by the name-enumeration tool"
		}
		records = append(records, externalRecord(req.RunID, host, status, "dnsx", model.MethodResolve, note))
	}
	return records, nil
}

// ParseExternalNames accepts plain hostname lines or JSONL objects containing
// a `host` field. Every candidate passes the configured DNS suffix classifier;
// apexes, malformed values, Unicode and out-of-scope names are discarded.
func ParseExternalNames(stdout []byte, configuredScope *scope.Scope) ([]string, error) {
	if configuredScope == nil {
		return nil, fmt.Errorf("configured scope is required to parse external names")
	}
	scanner, err := newOutputScanner(stdout, "external")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := string(scanner.Bytes())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		candidate := line
		if strings.HasPrefix(line, "{") {
			var probe struct {
				Host string `json:"host"`
			}
			if err := json.Unmarshal([]byte(line), &probe); err != nil {
				return nil, fmt.Errorf("external output line %d is malformed JSON: %w", lineNumber, err)
			}
			if probe.Host == "" {
				return nil, fmt.Errorf("external output line %d is missing a host field", lineNumber)
			}
			candidate = probe.Host
		}
		classified := configuredScope.Classify(candidate)
		if !classified.InScope || seen[classified.Normalized] {
			continue
		}
		seen[classified.Normalized] = true
		out = append(out, classified.Normalized)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read external output: %w", err)
	}
	return out, nil
}

// ParseDNSXNames validates every non-empty dnsx JSONL row. A malformed or
// incomplete row is an execution error, not evidence that a host had no answer.
func ParseDNSXNames(stdout []byte, configuredScope *scope.Scope) ([]string, error) {
	if configuredScope == nil {
		return nil, fmt.Errorf("configured scope is required to parse dnsx output")
	}
	scanner, err := newOutputScanner(stdout, "dnsx")
	if err != nil {
		return nil, err
	}
	seen := map[string]bool{}
	out := make([]string, 0)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		line := string(scanner.Bytes())
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var result struct {
			Host string `json:"host"`
		}
		if err := json.Unmarshal([]byte(line), &result); err != nil {
			return nil, fmt.Errorf("dnsx output line %d is not valid JSON: %w", lineNumber, err)
		}
		if strings.TrimSpace(result.Host) == "" {
			return nil, fmt.Errorf("dnsx output line %d is missing a host field", lineNumber)
		}
		classified := configuredScope.Classify(result.Host)
		if !classified.InScope || seen[classified.Normalized] {
			continue
		}
		seen[classified.Normalized] = true
		out = append(out, classified.Normalized)
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read dnsx output: %w", err)
	}
	return out, nil
}

func newOutputScanner(stdout []byte, backendName string) (*bufio.Scanner, error) {
	if len(stdout) > MaxOutputBytes {
		return nil, fmt.Errorf("%s output exceeds the %d-byte capture cap", backendName, MaxOutputBytes)
	}
	scanner := bufio.NewScanner(bytes.NewReader(stdout))
	scanner.Buffer(make([]byte, 0, 64*1024), MaxOutputBytes)
	return scanner, nil
}

func externalRecord(runID, host string, status model.Status, backendName, method, detail string) *model.Record {
	record := model.NewRecord(runID, host, status, model.Provenance{
		Backend: backendName,
		Method:  method,
		Detail:  detail,
		Fixture: false,
	}, true, "")
	if status == model.StatusNoAnswer {
		record.Notes = model.NoteNoAnswerNotNXDOMAIN
	} else {
		record.Notes = detail
	}
	return record
}

// DurationFromSeconds turns a bounded integer tool parameter into a process
// timeout. A zero value is replaced by the server default.
func DurationFromSeconds(seconds int) (time.Duration, error) {
	if seconds < 0 || seconds > 300 {
		return 0, fmt.Errorf("timeout_seconds must be between 1 and 300")
	}
	if seconds == 0 {
		return DefaultExternalTimeout, nil
	}
	return time.Duration(seconds) * time.Second, nil
}
