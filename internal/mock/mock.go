// Package mock implements the offline fixture backends. Fixture output is
// deterministic, labeled as synthetic, and performs no subprocess execution
// and no network traffic of any kind.
package mock

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/assets"
	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

// Trigger labels exercise non-positive statuses deterministically in fixture
// output.
const (
	TriggerTimeout   = "timeouthost"
	TriggerDNSError  = "dnserrorhost"
	FixtureConnector = "alias"
)

// Source maps hosts under the configured root to deterministic fixture data.
type Source struct {
	root   string
	tokens []string // preset wordlist doubles as the fixture token pool
}

func New(root string) *Source {
	var tokens []string
	for _, line := range strings.Split(assets.PresetSmall, "\n") {
		line = strings.TrimSpace(line)
		if line != "" && !strings.HasPrefix(line, "#") {
			tokens = append(tokens, line)
		}
	}
	sort.Strings(tokens)
	return &Source{root: root, tokens: tokens}
}

func (s *Source) Root() string { return s.root }

// PassiveNames returns the names the fixture passive source "knows": first
// 14 tokens, leaving some preset words discoverable only via bruteforce.
func (s *Source) PassiveNames() []string {
	out := make([]string, 0, len(s.tokens))
	n := 14
	if len(s.tokens) < n {
		n = len(s.tokens)
	}
	for _, t := range s.tokens[:n] {
		out = append(out, t+"."+s.root)
	}
	return out
}

// Words returns the preset wordlist (used by the bruteforce backend).
func (s *Source) Words() []string {
	out := append([]string{}, s.tokens...)
	return out
}

// Tokens returns the permutation token pool (used by candidate generation).
func (s *Source) Tokens() []string { return s.tokens }

func (s *Source) fixtureIP(token string) string {
	idx := 0
	for i, t := range s.tokens {
		if t == token {
			idx = i
			break
		}
	}
	return fmt.Sprintf("203.0.113.%d", 10+(idx%200))
}

// Lookup maps an in-scope host to a fixture response. An absent host is a
// no-answer, explicitly not an NXDOMAIN conclusion.
func (s *Source) Lookup(host string) (model.Status, model.DNSRecords, string) {
	norm, err := scope.Normalize(host)
	if err != nil {
		return model.StatusNoAnswer, nil, model.NoteNoAnswerNotNXDOMAIN
	}
	label := strings.TrimSuffix(norm, "."+s.root)
	if label == norm || label == "" || strings.Contains(label, ".") {
		return model.StatusNoAnswer, nil, model.NoteNoAnswerNotNXDOMAIN
	}
	switch label {
	case TriggerTimeout:
		return model.StatusTimeout, nil, "fixture backend simulates a resolver timeout for this label"
	case TriggerDNSError:
		return model.StatusDNSError, nil, "fixture backend simulates a resolver error for this label"
	}
	for i, t := range s.tokens {
		if t != label || i >= 16 {
			continue
		}
		recs := model.DNSRecords{"A": {s.fixtureIP(t)}}
		if label == "www" {
			recs["CNAME"] = []string{FixtureConnector + "." + s.root}
		}
		return model.StatusResolved, recs, ""
	}
	if label == FixtureConnector {
		return model.StatusResolved, model.DNSRecords{"CNAME": {"api." + s.root}}, ""
	}
	return model.StatusNoAnswer, nil, model.NoteNoAnswerNotNXDOMAIN
}

// Mutations implements a deterministic alterx-style permutation simulation:
// label parts of the seed hosts are combined with a bounded token pool.
func (s *Source) Mutations(seeds []string, max int) []string {
	seen := map[string]bool{}
	out := []string{}
	tokens := s.tokens
	if len(tokens) > 6 {
		tokens = tokens[:6]
	}
	add := func(host string) {
		if len(out) >= max {
			return
		}
		if seen[host] {
			return
		}
		seen[host] = true
		out = append(out, host)
	}
	if len(seeds) == 0 {
		return out
	}
	parts := []string{}
	for _, seed := range seeds {
		label := strings.TrimSuffix(seed, "."+s.root)
		for _, p := range splitLabel(label) {
			if p != "" && p != s.root {
				parts = append(parts, p)
			}
		}
	}
	sort.Strings(parts)
	for _, p := range parts {
		add(p + "." + s.root)
		for _, t := range tokens {
			if t == p {
				continue
			}
			add(t + "-" + p + "." + s.root)
			add(p + "-" + t + "." + s.root)
		}
	}
	return out
}

func splitLabel(label string) []string {
	return strings.FieldsFunc(label, func(r rune) bool {
		return r == '-' || r == '_' || r == '.'
	})
}

func fixtureProv(backendName, method, detail string) model.Provenance {
	return model.Provenance{Backend: backendName, Method: method, Detail: detail, Fixture: true}
}

func noteFixture(extra ...string) string {
	parts := append([]string{model.NoteFixtureLabel}, extra...)
	return strings.Join(parts, "; ")
}

// Discoverer is the fixture passive discovery backend.
type Discoverer struct{ Src *Source }

func (d *Discoverer) Discover(ctx context.Context, req backend.DiscoverRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names := d.Src.PassiveNames()
	if req.MaxRecords > 0 && len(names) > req.MaxRecords {
		names = names[:req.MaxRecords]
	}
	records := make([]*model.Record, 0, len(names))
	for _, host := range names {
		records = append(records, &model.Record{
			RunID:  req.RunID,
			Host:   host,
			Status: model.StatusCandidate,
			Provenance: []model.Provenance{
				fixtureProv("mock.subfinder", model.MethodPassive, "offline fixture passive source"),
			},
			ObservedAt: nowUTC(),
			InScope:    true,
			Notes:      noteFixture("candidate name from the fixture passive source"),
		})
	}
	return records, nil
}

// Generator is the fixture candidate-generation backend (alterx-style
// permutation simulation, implemented in-process).
type Generator struct{ Src *Source }

func (g *Generator) Generate(ctx context.Context, req backend.CandidateRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	names := g.Src.Mutations(req.Seeds, req.MaxOut)
	records := make([]*model.Record, 0, len(names))
	for _, host := range names {
		records = append(records, &model.Record{
			RunID:  req.RunID,
			Host:   host,
			Status: model.StatusCandidate,
			Provenance: []model.Provenance{
				fixtureProv("mock.alterx", model.MethodCandidateGen, "offline permutation simulation"),
			},
			ObservedAt: nowUTC(),
			InScope:    true,
			Notes:      noteFixture("permutation candidate"),
		})
	}
	return records, nil
}

// Bruteforcer is the fixture bruteforce backend over the pinned preset
// wordlist.
type Bruteforcer struct{ Src *Source }

func (b *Bruteforcer) Bruteforce(ctx context.Context, req backend.BruteforceRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	words := b.Src.Words()
	if req.MaxWords > 0 && len(words) > req.MaxWords {
		words = words[:req.MaxWords]
	}
	records := make([]*model.Record, 0, len(words))
	for _, w := range words {
		host := w + "." + b.Src.Root()
		status, recs, note := b.Src.Lookup(host)
		r := &model.Record{
			RunID:      req.RunID,
			Host:       host,
			Status:     status,
			Provenance: []model.Provenance{fixtureProv("mock.dnsx", model.MethodBruteforce, "fixture dataset; preset wordlist "+req.Preset)},
			ObservedAt: nowUTC(),
			InScope:    true,
			Notes:      noteFixture(note),
		}
		if len(recs) > 0 {
			r.FixtureDNSRecords = recs
		}
		records = append(records, r)
	}
	return records, nil
}

// Resolver is the fixture resolution backend (simulated A/AAAA/CNAME answers).
type Resolver struct{ Src *Source }

func (r *Resolver) Resolve(ctx context.Context, req backend.ResolveRequest) ([]*model.Record, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	hosts := req.Hosts
	if req.MaxHosts > 0 && len(hosts) > req.MaxHosts {
		hosts = hosts[:req.MaxHosts]
	}
	records := make([]*model.Record, 0, len(hosts))
	for _, raw := range hosts {
		host, err := scope.Normalize(raw)
		if err != nil {
			host = raw
		}
		status, recs, note := r.Src.Lookup(host)
		rec := &model.Record{
			RunID:      req.RunID,
			Host:       host,
			Status:     status,
			Provenance: []model.Provenance{fixtureProv("mock.dnsx", model.MethodResolve, "fixture dataset A/AAAA/CNAME answers")},
			ObservedAt: nowUTC(),
			InScope:    true,
			Notes:      noteFixture(note),
		}
		if len(recs) > 0 {
			rec.FixtureDNSRecords = recs
		}
		records = append(records, rec)
	}
	return records, nil
}

func nowUTC() time.Time { return time.Now().UTC() }
