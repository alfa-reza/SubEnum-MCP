// Package model defines the enumeration record, its status lifecycle and
// provenance union semantics.
package model

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

// Status is the lifecycle state of a host within a run.
//
// Empty answers are never reported as NXDOMAIN: an absent answer is recorded
// as NoAnswer and must not be interpreted as proof of nonexistence.
type Status string

const (
	StatusCandidate Status = "candidate"
	StatusResolved  Status = "resolved"
	StatusNoAnswer  Status = "no_answer"
	StatusTimeout   Status = "timeout"
	StatusDNSError  Status = "dns_error"
)

func (s Status) Valid() bool {
	switch s {
	case StatusCandidate, StatusResolved, StatusNoAnswer, StatusTimeout, StatusDNSError:
		return true
	}
	return false
}

// StatusRank orders conflicts when a host is observed multiple times. Higher
// rank wins on merge; a resolved observation should never be silently
// downgraded by a later no-answer observation.
var StatusRank = map[Status]int{
	StatusCandidate: 0,
	StatusTimeout:   1,
	StatusDNSError:  1,
	StatusNoAnswer:  2,
	StatusResolved:  3,
}

// Provenance methods.
const (
	MethodPassive      = "passive"
	MethodCandidateGen = "candidate_generation"
	MethodBruteforce   = "bruteforce"
	MethodResolve      = "resolve"
)

// NoteNoAnswerNotNXDOMAIN is attached wherever an empty answer set could be
// misread as a negative DNS response code.
const NoteNoAnswerNotNXDOMAIN = "no positive DNS answer observed; this does not distinguish timeout, resolver failure, or NXDOMAIN"

// NoteFixtureLabel marks outputs produced by the offline fixture backend so
// they can never be confused with observed results.
const NoteFixtureLabel = "fixture output: synthetic offline data, not an observed result"

// Provenance describes one origin observation for a host.
type Provenance struct {
	Backend string `json:"backend"`
	Method  string `json:"method"`
	Detail  string `json:"detail,omitempty"`
	Fixture bool   `json:"fixture"`
}

func (p Provenance) Key() string {
	return p.Backend + "|" + p.Method + "|" + p.Detail + "|" + fmt.Sprintf("%t", p.Fixture)
}

// DNSRecords maps RR type to observed or synthetic values.
type DNSRecords map[string][]string

// Record is the minimum exported enumeration unit.
type Record struct {
	RunID      string       `json:"run_id"`
	Host       string       `json:"host"`
	Status     Status       `json:"status"`
	Provenance []Provenance `json:"provenance"`
	// FixtureDNSRecords is populated only when the observation comes from the
	// offline fixture backend; it must never be presented as live DNS data.
	FixtureDNSRecords  DNSRecords `json:"fixture_dns_records,omitempty"`
	ObservedDNSRecords DNSRecords `json:"observed_dns_records,omitempty"`
	ObservedAt         time.Time  `json:"observed_at"`
	InScope            bool       `json:"in_scope"`
	DropReason         string     `json:"drop_reason,omitempty"`
	Notes              string     `json:"notes,omitempty"`
}

func NewRecord(runID, host string, status Status, prov Provenance, inScope bool, dropReason string) *Record {
	return &Record{
		RunID:      runID,
		Host:       host,
		Status:     status,
		Provenance: []Provenance{prov},
		ObservedAt: time.Now().UTC(),
		InScope:    inScope,
		DropReason: dropReason,
	}
}

// AddProvenance unions provenance entries, de-duplicating by key.
func (r *Record) AddProvenance(ps ...Provenance) {
	seen := make(map[string]bool, len(r.Provenance))
	for _, p := range r.Provenance {
		seen[p.Key()] = true
	}
	for _, p := range ps {
		if seen[p.Key()] {
			continue
		}
		seen[p.Key()] = true
		r.Provenance = append(r.Provenance, p)
	}
	sortProvenance(r.Provenance)
}

func sortProvenance(ps []Provenance) {
	sort.SliceStable(ps, func(i, j int) bool { return ps[i].Key() < ps[j].Key() })
}

// Merge folds src into dst: provenance union, status escalation by rank,
// fixture DNS record union and earliest observation time.
func Merge(dst, src *Record) {
	dst.AddProvenance(src.Provenance...)
	if StatusRank[src.Status] > StatusRank[dst.Status] {
		dst.Status = src.Status
	}
	if src.ObservedAt.Before(dst.ObservedAt) {
		dst.ObservedAt = src.ObservedAt
	}
	if len(src.FixtureDNSRecords) > 0 {
		if dst.FixtureDNSRecords == nil {
			dst.FixtureDNSRecords = DNSRecords{}
		}
		for rr, vals := range src.FixtureDNSRecords {
			dst.FixtureDNSRecords[rr] = UnionStrings(dst.FixtureDNSRecords[rr], vals)
		}
	}
	if len(src.ObservedDNSRecords) > 0 {
		if dst.ObservedDNSRecords == nil {
			dst.ObservedDNSRecords = DNSRecords{}
		}
		for rr, vals := range src.ObservedDNSRecords {
			dst.ObservedDNSRecords[rr] = UnionStrings(dst.ObservedDNSRecords[rr], vals)
		}
	}
	if src.Notes != "" && !strings.Contains(dst.Notes, src.Notes) {
		if dst.Notes != "" {
			dst.Notes = dst.Notes + "; " + src.Notes
		} else {
			dst.Notes = src.Notes
		}
	}
}

func UnionStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a)+len(b))
	out := make([]string, 0, len(a)+len(b))
	for _, s := range append(append([]string{}, a...), b...) {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	sort.Strings(out)
	return out
}

// CountByStatus tallies records.
func CountByStatus(records []*Record) map[Status]int {
	out := map[Status]int{}
	for _, r := range records {
		out[r.Status]++
	}
	return out
}
