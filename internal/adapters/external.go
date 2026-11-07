package adapters

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"sort"
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
	scanner, err := newOutputScanner(stdout, "subfinder")
	if err != nil {
		return nil, err
	}
	records := make([]*model.Record, 0)
	byHost := map[string]*model.Record{}
	for scanner.Scan() {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var row struct {
			Host    string   `json:"host"`
			Source  string   `json:"source"`
			Sources []string `json:"sources"`
		}
		if strings.HasPrefix(strings.TrimSpace(scanner.Text()), "{") {
			if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
				return nil, fmt.Errorf("invalid subfinder JSON: %w", err)
			}
		} else {
			row.Host = strings.TrimSpace(scanner.Text())
		}
		if row.Host == "" {
			return nil, fmt.Errorf("subfinder output missing host")
		}
		classified := e.scope.Classify(row.Host)
		if !classified.InScope {
			continue
		}
		record := byHost[classified.Normalized]
		if record == nil {
			if len(records) >= req.MaxRecords {
				continue
			}
			record = externalRecord(req.RunID, classified.Normalized, model.StatusCandidate, "subfinder", model.MethodPassive, "passive source result; not independently validated")
			records = append(records, record)
			byHost[classified.Normalized] = record
		}
		if row.Source != "" {
			row.Sources = append(row.Sources, row.Source)
		}
		for _, source := range row.Sources {
			if len(source) > 100 || strings.ContainsAny(source, "\r\n\t") {
				return nil, fmt.Errorf("invalid subfinder source")
			}
			if source != "" {
				record.AddProvenance(model.Provenance{Backend: "subfinder", Method: model.MethodPassive, Detail: "source: " + source})
			}
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read subfinder output: %w", err)
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
	stdout, _, runErr := e.runner.Run(ctx, spec)
	timedOut := runErr != nil && (errors.Is(runErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded))
	observations, parseErr := parseDNSXObservations(stdout, e.scope)
	if parseErr != nil && timedOut {
		observations, parseErr = parseDNSXObservations(trimTrailingPartialLine(stdout), e.scope)
	}
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w (and output parse failed: %v)", runErr, parseErr)
		}
		return nil, parseErr
	}
	if runErr != nil && !timedOut {
		return nil, runErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	records := make([]*model.Record, 0, len(words))
	for _, word := range words {
		host := word + "." + e.scope.Root()
		if obs, ok := observations[host]; ok {
			status, note := dnsxStatusFromObservation(obs, len(obs.Records) > 0)
			record := externalRecord(req.RunID, host, status, "dnsx", model.MethodBruteforce, note)
			record.ObservedDNSRecords = obs.Records
			records = append(records, record)
			continue
		}
		status, note := model.StatusNoAnswer, model.NoteNoAnswerNotNXDOMAIN
		if timedOut {
			status, note = model.StatusTimeout, "backend timed out before a response was observed for this host; retry with a smaller max_words or larger timeout_seconds"
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
	stdout, _, runErr := e.runner.Run(ctx, spec)
	timedOut := runErr != nil && (errors.Is(runErr, context.DeadlineExceeded) || errors.Is(ctx.Err(), context.DeadlineExceeded))
	observations, parseErr := parseDNSXObservations(stdout, e.scope)
	if parseErr != nil && timedOut {
		observations, parseErr = parseDNSXObservations(trimTrailingPartialLine(stdout), e.scope)
	}
	if parseErr != nil {
		if runErr != nil {
			return nil, fmt.Errorf("%w (and output parse failed: %v)", runErr, parseErr)
		}
		return nil, parseErr
	}
	if runErr != nil && !timedOut {
		return nil, runErr
	}
	if err := ctx.Err(); err != nil && !errors.Is(err, context.DeadlineExceeded) {
		return nil, err
	}

	records := make([]*model.Record, 0, len(hosts))
	for _, host := range hosts {
		if obs, ok := observations[host]; ok {
			status, note := dnsxStatusFromObservation(obs, len(obs.Records) > 0)
			record := externalRecord(req.RunID, host, status, "dnsx", model.MethodResolve, note)
			record.ObservedDNSRecords = obs.Records
			records = append(records, record)
			continue
		}
		status, note := model.StatusNoAnswer, model.NoteNoAnswerNotNXDOMAIN
		if timedOut {
			status, note = model.StatusTimeout, "backend timed out before a response was observed for this host; retry with host_offset/host_limit or a larger timeout_seconds"
		}
		records = append(records, externalRecord(req.RunID, host, status, "dnsx", model.MethodResolve, note))
	}
	return records, nil
}

func trimTrailingPartialLine(b []byte) []byte {
	if len(b) == 0 {
		return b
	}
	i := bytes.LastIndexByte(b, '\n')
	if i < 0 {
		return nil
	}
	return b[:i+1]
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

type dnsxResult struct {
	Records    model.DNSRecords
	StatusCode string
}

// ParseDNSXNames validates every non-empty dnsx JSONL row. A malformed or
// incomplete row is an execution error, not evidence that a host had no answer.
func ParseDNSXNames(stdout []byte, configuredScope *scope.Scope) ([]string, error) {
	results, err := parseDNSXObservations(stdout, configuredScope)
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(results))
	for host := range results {
		names = append(names, host)
	}
	sort.Strings(names)
	return names, nil
}

func parseDNSXObservations(stdout []byte, configuredScope *scope.Scope) (map[string]dnsxResult, error) {
	if configuredScope == nil {
		return nil, fmt.Errorf("configured scope is required to parse dnsx output")
	}
	scanner, err := newOutputScanner(stdout, "dnsx")
	if err != nil {
		return nil, err
	}
	out := map[string]dnsxResult{}
	for line := 1; scanner.Scan(); line++ {
		if strings.TrimSpace(scanner.Text()) == "" {
			continue
		}
		var row struct {
			Host       string   `json:"host"`
			A          []string `json:"a"`
			AAAA       []string `json:"aaaa"`
			CNAME      []string `json:"cname"`
			StatusCode string   `json:"status_code"`
			Error      string   `json:"error"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &row); err != nil {
			return nil, fmt.Errorf("dnsx output line %d is not valid JSON: %w", line, err)
		}
		if strings.TrimSpace(row.Host) == "" {
			return nil, fmt.Errorf("dnsx output line %d is missing a host field", line)
		}
		classified := configuredScope.Classify(row.Host)
		if !classified.InScope {
			continue
		}
		res := out[classified.Normalized]
		if res.Records == nil {
			res.Records = model.DNSRecords{}
		}
		if row.StatusCode != "" {
			res.StatusCode = row.StatusCode
		}
		if row.Error != "" && res.StatusCode == "" {
			res.StatusCode = "ERROR"
		}
		for typ, vals := range map[string][]string{"A": row.A, "AAAA": row.AAAA, "CNAME": row.CNAME} {
			for _, value := range vals {
				valid := false
				if typ == "CNAME" {
					valid = scope.ValidateHostname(strings.TrimSuffix(value, "."), scope.DefaultPolicy()) == nil
				} else if addr, err := netip.ParseAddr(value); err == nil {
					valid = (typ == "A" && addr.Is4()) || (typ == "AAAA" && addr.Is6() && !addr.Is4In6())
				}
				if !valid {
					return nil, fmt.Errorf("dnsx output line %d contains invalid %s value", line, typ)
				}
			}
			if len(vals) > 0 {
				res.Records[typ] = model.UnionStrings(res.Records[typ], vals)
			}
		}
		out[classified.Normalized] = res
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("read dnsx output: %w", err)
	}
	return out, nil
}

// parseDNSXRecords is kept for compatibility with internal tests/callers that
// only need positive answer records.
func parseDNSXRecords(stdout []byte, configuredScope *scope.Scope) (map[string]model.DNSRecords, error) {
	obs, err := parseDNSXObservations(stdout, configuredScope)
	if err != nil {
		return nil, err
	}
	out := map[string]model.DNSRecords{}
	for host, r := range obs {
		if len(r.Records) > 0 {
			out[host] = r.Records
		}
	}
	return out, nil
}

func dnsxStatusFromObservation(obs dnsxResult, hasAnswers bool) (model.Status, string) {
	if hasAnswers {
		return model.StatusResolved, "DNS response observed"
	}
	switch strings.ToUpper(strings.TrimSpace(obs.StatusCode)) {
	case "NXDOMAIN":
		return model.StatusNoAnswer, "NXDOMAIN (authoritative negative response)"
	case "SERVFAIL", "REFUSED", "NOTIMP", "FORMERR", "ERROR":
		return model.StatusDNSError, fmt.Sprintf("DNS error/status: %s", obs.StatusCode)
	case "TIMEOUT":
		return model.StatusTimeout, "DNS query timed out"
	case "NOERROR":
		return model.StatusNoAnswer, "no positive DNS answer observed (NOERROR); no A/AAAA/CNAME answer in response"
	case "":
		return model.StatusNoAnswer, model.NoteNoAnswerNotNXDOMAIN
	default:
		return model.StatusNoAnswer, fmt.Sprintf("no positive DNS answer observed (status %s)", obs.StatusCode)
	}
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
