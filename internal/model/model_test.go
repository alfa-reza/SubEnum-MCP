package model

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/google/jsonschema-go/jsonschema"
)

func TestRecordStatusSchemaExplainsEvidence(t *testing.T) {
	schema, err := jsonschema.ForType(reflect.TypeFor[Record](), nil)
	if err != nil {
		t.Fatal(err)
	}
	status := schema.Properties["status"]
	if status == nil || !strings.Contains(status.Description, "no_answer is inconclusive") || !strings.Contains(status.Description, "not proof") {
		t.Fatalf("status schema does not explain evidence limits: %+v", status)
	}
}

func TestProvenanceUnionDedupe(t *testing.T) {
	rec := NewRecord("r1", "api.example.com", StatusCandidate, Provenance{
		Backend: "mock.subfinder", Method: MethodPassive, Detail: "fixture", Fixture: true,
	}, true, "")
	rec.AddProvenance(
		Provenance{Backend: "mock.subfinder", Method: MethodPassive, Detail: "fixture", Fixture: true},
		Provenance{Backend: "mock.alterx", Method: MethodCandidateGen, Detail: "fixture", Fixture: true},
		Provenance{Backend: "mock.dnsx", Method: MethodResolve, Detail: "fixture", Fixture: true},
		Provenance{Backend: "mock.alterx", Method: MethodCandidateGen, Detail: "fixture", Fixture: true},
	)
	if len(rec.Provenance) != 3 {
		t.Fatalf("provenance = %d entries, want 3 (dedupe by backend|method|detail|fixture)", len(rec.Provenance))
	}
}

func TestMergeStatusEscalation(t *testing.T) {
	base := &Record{Host: "api.example.com", Status: StatusCandidate, ObservedAt: time.Now().UTC(), Provenance: []Provenance{{Backend: "a", Method: MethodPassive, Fixture: true}}}

	candidate := &Record{Host: base.Host, Status: StatusCandidate, ObservedAt: time.Now().UTC(), Provenance: []Provenance{{Backend: "b", Method: MethodCandidateGen, Fixture: true}}}
	Merge(base, candidate)
	if base.Status != StatusCandidate {
		t.Fatalf("candidate merge changed status to %q", base.Status)
	}

	resolved := &Record{Host: base.Host, Status: StatusResolved, ObservedAt: time.Now().UTC(), Provenance: []Provenance{{Backend: "c", Method: MethodResolve, Fixture: true}}, FixtureDNSRecords: DNSRecords{"A": {"203.0.113.10"}}}
	Merge(base, resolved)
	if base.Status != StatusResolved {
		t.Fatalf("resolved should win, got %q", base.Status)
	}

	// A later no-answer must not downgrade a resolved record.
	noAns := &Record{Host: base.Host, Status: StatusNoAnswer, ObservedAt: time.Now().UTC(), Provenance: []Provenance{{Backend: "d", Method: MethodResolve, Fixture: true}}}
	Merge(base, noAns)
	if base.Status != StatusResolved {
		t.Fatalf("no_answer downgraded resolved to %q", base.Status)
	}
	if len(base.Provenance) != 4 {
		t.Fatalf("provenance union = %d, want 4", len(base.Provenance))
	}

	// Fixture DNS records union across merges.
	more := &Record{Host: base.Host, Status: StatusResolved, FixtureDNSRecords: DNSRecords{"AAAA": {"2001:db8::10"}}}
	Merge(base, more)
	if len(base.FixtureDNSRecords["A"]) != 1 || len(base.FixtureDNSRecords["AAAA"]) != 1 {
		t.Fatalf("fixture record union broken: %v", base.FixtureDNSRecords)
	}
}

func TestStatusValidAndRank(t *testing.T) {
	for _, s := range []Status{StatusCandidate, StatusResolved, StatusNoAnswer, StatusTimeout, StatusDNSError} {
		if !s.Valid() {
			t.Errorf("status %q should be valid", s)
		}
		if _, ok := StatusRank[s]; !ok {
			t.Errorf("status %q missing rank", s)
		}
	}
	if Status("nxdomain").Valid() {
		t.Error("nxdomain must not be a record status")
	}
	if StatusRank[StatusResolved] <= StatusRank[StatusNoAnswer] {
		t.Error("resolved must outrank no_answer")
	}
}

func TestNewRecordSetsObservedUTC(t *testing.T) {
	rec := NewRecord("r1", "x.example.com", StatusCandidate, Provenance{Backend: "m", Method: MethodPassive}, true, "")
	if rec.ObservedAt.Location() != time.UTC {
		t.Fatalf("ObservedAt not UTC: %v", rec.ObservedAt.Location())
	}
}

func TestUnionStrings(t *testing.T) {
	got := UnionStrings([]string{"b", "a"}, []string{"a", "c"})
	if len(got) != 3 || got[0] != "a" || got[1] != "b" || got[2] != "c" {
		t.Fatalf("UnionStrings = %v", got)
	}
}
