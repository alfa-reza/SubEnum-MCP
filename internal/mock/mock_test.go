package mock

import (
	"context"
	"os/exec"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// The fixture backends hold no runner and no network client: subprocess and
// traffic freedom is structural. These tests pin that the outputs behave and
// are labeled as fixtures.

func newSource(t *testing.T, root string) *Source {
	t.Helper()
	return New(root)
}

func TestPassiveDiscoveryIsFixtureAndOffline(t *testing.T) {
	src := newSource(t, "example.com")
	d := &Discoverer{Src: src}
	recs, err := d.Discover(context.Background(), backend.DiscoverRequest{RunID: "r1", Root: src.Root(), MaxRecords: 100})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) == 0 {
		t.Fatal("fixture passive source returned nothing")
	}
	for _, rec := range recs {
		if !strings.HasSuffix(rec.Host, ".example.com") {
			t.Fatalf("out-of-scope fixture host %q", rec.Host)
		}
		if rec.Status != model.StatusCandidate {
			t.Fatalf("passive record status = %q, want candidate", rec.Status)
		}
		if len(rec.Provenance) != 1 || !rec.Provenance[0].Fixture || rec.Provenance[0].Backend != "mock.subfinder" {
			t.Fatalf("provenance = %+v", rec.Provenance)
		}
		if !strings.Contains(rec.Notes, model.NoteFixtureLabel) {
			t.Fatalf("fixture label missing in notes: %q", rec.Notes)
		}
		if rec.FixtureDNSRecords != nil {
			t.Fatalf("passive candidates must not carry DNS records: %v", rec.FixtureDNSRecords)
		}
	}
}

func TestLookupMapAndSpecialTriggers(t *testing.T) {

	src := newSource(t, "example.com")
	status, recs, _ := src.Lookup("api.example.com")
	if status != model.StatusResolved || recs["A"] == nil {
		t.Fatalf("api lookup = %q %v", status, recs)
	}
	status, _, _ = src.Lookup("alias.example.com")
	if status != model.StatusResolved {
		t.Fatalf("alias lookup = %q", status)
	}
	status, _, note := src.Lookup("unknown-name.example.com")
	if status != model.StatusNoAnswer {
		t.Fatalf("unknown lookup = %q, want no_answer", status)
	}
	if !strings.Contains(note, model.NoteNoAnswerNotNXDOMAIN) {
		t.Fatalf("empty answer must not be concluded NXDOMAIN; note = %q", note)
	}
	status, _, _ = src.Lookup("timeouthost.example.com")
	if status != model.StatusTimeout {
		t.Fatalf("timeout trigger = %q", status)
	}
	status, _, _ = src.Lookup("dnserrorhost.example.com")
	if status != model.StatusDNSError {
		t.Fatalf("dns_error trigger = %q", status)
	}
}

func TestResolverBruteforcerLabelFixture(t *testing.T) {

	src := newSource(t, "example.com")
	res := &Resolver{Src: src}
	recs, err := res.Resolve(context.Background(), backend.ResolveRequest{
		RunID: "r1", Root: src.Root(),
		Hosts: []string{"API.example.com", "missing.example.com", "timeouthost.example.com", "dnserrorhost.example.com"},
	})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]model.Status{}
	for _, rec := range recs {
		got[rec.Host] = rec.Status
		if rec.Provenance[0].Backend != "mock.dnsx" || !rec.Provenance[0].Fixture {
			t.Fatalf("provenance = %+v", rec.Provenance)
		}
		if !strings.Contains(rec.Notes, model.NoteFixtureLabel) {
			t.Fatalf("fixture label missing: %q", rec.Notes)
		}
	}
	if got["api.example.com"] != model.StatusResolved {
		t.Fatalf("normalized resolve = %v", got)
	}
	if got["missing.example.com"] != model.StatusNoAnswer {
		t.Fatalf("missing host = %v", got)
	}
	if got["timeouthost.example.com"] != model.StatusTimeout || got["dnserrorhost.example.com"] != model.StatusDNSError {
		t.Fatalf("trigger statuses = %v", got)
	}

	br := &Bruteforcer{Src: src}
	brecs, err := br.Bruteforce(context.Background(), backend.BruteforceRequest{RunID: "r1", Root: src.Root(), Preset: "preset-small"})
	if err != nil {
		t.Fatal(err)
	}
	if len(brecs) != len(src.Words()) {
		t.Fatalf("bruteforce words = %d, want %d", len(brecs), len(src.Words()))
	}
	for _, rec := range brecs {
		if rec.Provenance[0].Method != model.MethodBruteforce {
			t.Fatalf("method = %q", rec.Provenance[0].Method)
		}
		if rec.Status == model.StatusResolved && rec.FixtureDNSRecords == nil {
			t.Fatalf("resolved fixture record without DNS data: %s", rec.Host)
		}
	}
}

func TestMutationsDeterministicAndCapped(t *testing.T) {
	src := newSource(t, "example.com")
	seeds := []string{"api-dev.example.com", "www.example.com"}
	a, err := (&Generator{Src: src}).Generate(context.Background(), backend.CandidateRequest{RunID: "r1", Root: src.Root(), Seeds: seeds, MaxOut: 50})
	if err != nil {
		t.Fatal(err)
	}
	b, err := (&Generator{Src: src}).Generate(context.Background(), backend.CandidateRequest{RunID: "r1", Root: src.Root(), Seeds: seeds, MaxOut: 50})
	if err != nil {
		t.Fatal(err)
	}
	if len(a) == 0 || len(a) != len(b) {
		t.Fatalf("mutations not deterministic: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i].Host != b[i].Host {
			t.Fatalf("mutation order differs at %d", i)
		}
	}
	capped, err := (&Generator{Src: src}).Generate(context.Background(), backend.CandidateRequest{RunID: "r1", Root: src.Root(), Seeds: seeds, MaxOut: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(capped) != 3 {
		t.Fatalf("cap not enforced: %d", len(capped))
	}
	for _, rec := range capped {
		if !strings.HasSuffix(rec.Host, ".example.com") {
			t.Fatalf("candidate escaped scope: %q", rec.Host)
		}
		if rec.Status != model.StatusCandidate || rec.Provenance[0].Backend != "mock.alterx" {
			t.Fatalf("candidate record wrong: %+v", rec)
		}
	}
}

func TestGeneratorRequiresSeeds(t *testing.T) {
	src := newSource(t, "example.com")
	recs, err := (&Generator{Src: src}).Generate(context.Background(), backend.CandidateRequest{RunID: "r1", Root: src.Root(), Seeds: nil, MaxOut: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 0 {
		t.Fatalf("no seeds should produce no candidates, got %d", len(recs))
	}
}

// TestMockPackageImportsNoExecNet pins the structural guarantee that fixture
// backends cannot spawn processes or send traffic: the non-test mock package
// must not import os/exec or any network package.
func TestMockPackageImportsNoExecNet(t *testing.T) {
	cmd := exec.Command("go", "list", "-f", "{{join .Imports \"\\n\"}}", "github.com/alfa-reza/SubEnum-MCP/internal/mock")
	out, err := cmd.Output()
	if err != nil {
		t.Skipf("go list unavailable: %v", err)
	}
	for _, imp := range strings.Split(string(out), "\n") {
		imp = strings.TrimSpace(imp)
		if imp == "os/exec" || imp == "net" || imp == "net/http" || imp == "crypto/tls" {
			t.Fatalf("fixture package must not import %q", imp)
		}
	}
}

func TestFixturePipelineCalls(t *testing.T) {
	src := newSource(t, "example.com")
	if _, err := (&Discoverer{Src: src}).Discover(context.Background(), backend.DiscoverRequest{RunID: "r2", Root: src.Root()}); err != nil {
		t.Fatal(err)
	}
	if _, err := (&Bruteforcer{Src: src}).Bruteforce(context.Background(), backend.BruteforceRequest{RunID: "r2", Root: src.Root(), Preset: "preset-small"}); err != nil {
		t.Fatal(err)
	}
}
