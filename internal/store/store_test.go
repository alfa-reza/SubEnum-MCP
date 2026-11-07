package store

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func timeNowUTC() time.Time { return time.Now().UTC() }

func newTestStore(t *testing.T) *Store {
	t.Helper()
	s, err := Open(t.TempDir(), "example.com")
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func rec(runID, host, status string, inScope bool, dropReason string) *model.Record {
	return &model.Record{
		RunID:      runID,
		Host:       host,
		Status:     model.Status(status),
		Provenance: []model.Provenance{{Backend: "mock.test", Method: model.MethodResolve, Fixture: true}},
		ObservedAt: timeNowUTC(),
		InScope:    inScope,
		DropReason: dropReason,
	}
}

func TestOpen_CreatesManagedDirs(t *testing.T) {
	s := newTestStore(t)
	for _, sub := range []string{"runs", "exports", "work"} {
		fi, err := os.Lstat(filepath.Join(s.Dir(), sub))
		if err != nil || !fi.IsDir() {
			t.Fatalf("managed dir %s missing: %v", sub, err)
		}
	}
}

func TestRunLifecycleAndUpsertMerge(t *testing.T) {
	s := newTestStore(t)
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.Run(run.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.LatestRun(); err != nil {
		t.Fatal(err)
	}

	r1, err := run.Upsert(rec(run.ID, "api.example.com", "candidate", true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if r1.Status != model.StatusCandidate {
		t.Fatalf("status %q", r1.Status)
	}
	r2, err := run.Upsert(&model.Record{
		RunID:      run.ID,
		Host:       "api.example.com",
		Status:     model.StatusResolved,
		Provenance: []model.Provenance{{Backend: "mock.dnsx", Method: model.MethodResolve, Fixture: true}},
		ObservedAt: time.Now().UTC(),
		InScope:    true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if r2.Status != model.StatusResolved {
		t.Fatalf("merge did not escalate status: %q", r2.Status)
	}
	if len(r2.Provenance) != 2 {
		t.Fatalf("provenance entries = %d, want 2", len(r2.Provenance))
	}
	if run.Count() != 1 {
		t.Fatalf("count = %d, want 1 (dedupe by host)", run.Count())
	}
}

func TestDroppedRecordCannotOverwriteInScopeHost(t *testing.T) {
	s := newTestStore(t)
	run, _ := s.CreateRun()
	if _, err := run.Upsert(rec(run.ID, "api.example.com", "resolved", true, "")); err != nil {
		t.Fatal(err)
	}
	if _, err := run.Upsert(rec(run.ID, "api.example.com", "candidate", false, "malformed_hostname")); err != nil {
		t.Fatal(err)
	}
	if run.Count() != 2 || len(run.InScope("")) != 1 || len(run.Dropped()) != 1 {
		t.Fatalf("dropped/in-scope partition collided: count=%d in_scope=%+v dropped=%+v", run.Count(), run.InScope(""), run.Dropped())
	}
	got, ok := run.Get("api.example.com")
	if !ok || got.Status != model.StatusResolved || !got.InScope {
		t.Fatalf("in-scope host was overwritten: %+v, ok=%v", got, ok)
	}
}

func TestUpsertInvalidStatus(t *testing.T) {
	s := newTestStore(t)
	run, _ := s.CreateRun()
	if _, err := run.Upsert(rec(run.ID, "api.example.com", "nxdomain", true, "")); err == nil {
		t.Fatal("expected error for invalid status nxdomain")
	}
}

func TestUpsertRejectsRecordFromDifferentRun(t *testing.T) {
	s := newTestStore(t)
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Upsert(rec("r20261106000000-deadbeef", "api.example.com", "candidate", true, "")); err == nil {
		t.Fatal("record tagged with a different run id was accepted")
	}
}

func TestUpsertWriteFailureDoesNotMutateRunState(t *testing.T) {
	s := newTestStore(t)
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := run.Upsert(rec(run.ID, "api.example.com", "candidate", true, "")); err != nil {
		t.Fatal(err)
	}
	run.rel = "../outside.jsonl"
	if _, err := run.Upsert(rec(run.ID, "api.example.com", "resolved", true, "")); err == nil {
		t.Fatal("expected rooted append to reject a traversal path")
	}
	got, ok := run.Get("api.example.com")
	if !ok || got.Status != model.StatusCandidate || len(got.Provenance) != 1 {
		t.Fatalf("failed append mutated in-memory record: %+v, ok=%v", got, ok)
	}
}

func TestLoadRejectsRecordTaggedWithDifferentRun(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	wrongRun, err := json.Marshal(rec("r20261106000000-deadbeef", "api.example.com", "resolved", true, ""))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(run.Path(), append(wrongRun, '\n'), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "example.com"); err == nil {
		t.Fatal("persisted record tagged with a different run id was accepted")
	}
}

func TestSafeNames(t *testing.T) {
	bad := []string{"", "..", "../evil", "a/b", "a\\b", "sub..dir", ".hidden", "A", "with space", "-lead", "x!"}
	for _, b := range bad {
		if err := SafeName(b); err == nil {
			t.Errorf("SafeName(%q) expected error", b)
		}
	}
	good := []string{"run1", "export-20261106t120000z", "ab_12", "a-b-1"}
	for _, g := range good {
		if err := SafeName(g); err != nil {
			t.Errorf("SafeName(%q): %v", g, err)
		}
	}
}

func TestSafeRunID(t *testing.T) {
	if err := SafeRunID("../../etc/passwd"); err == nil {
		t.Fatal("traversal accepted")
	}
	if err := SafeRunID("r20261106000000-deadbeef"); err != nil {
		t.Fatalf("valid id rejected: %v", err)
	}
	if err := SafeRunID("R20261106000000-deadbeef"); err == nil {
		t.Fatal("uppercase id accepted")
	}
	if err := SafeRunID(""); err == nil {
		t.Fatal("empty id accepted")
	}
}

func TestInScopeAndDroppedPartition(t *testing.T) {
	s := newTestStore(t)
	run, _ := s.CreateRun()
	run.Upsert(rec(run.ID, "a.example.com", "candidate", true, ""))
	run.Upsert(rec(run.ID, "evil.test", "candidate", false, "out_of_scope"))
	inScope := run.InScope("")
	if len(inScope) != 1 || inScope[0].Host != "a.example.com" {
		t.Fatalf("in-scope partition wrong: %+v", inScope)
	}
	if len(run.Dropped()) != 1 || run.Dropped()[0].DropReason != "out_of_scope" {
		t.Fatalf("dropped partition = %+v", run.Dropped())
	}
	filtered := run.InScope(model.StatusResolved)
	if len(filtered) != 0 {
		t.Fatalf("status filter = %+v", filtered)
	}
}

func TestPersistenceAcrossReopen(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	run, _ := s.CreateRun()
	run.Upsert(rec(run.ID, "api.example.com", "resolved", true, ""))

	s2, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s2.Close() })
	run2, err := s2.Run(run.ID)
	if err != nil {
		t.Fatal(err)
	}
	if run2.Count() != 1 {
		t.Fatalf("reopen count = %d", run2.Count())
	}
	got, ok := run2.Get("api.example.com")
	if !ok || got.Status != model.StatusResolved {
		t.Fatalf("persisted record wrong: %+v", got)
	}
}

func TestReopenRejectsMissingRecords(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(run.Path()); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, "example.com")
	if err == nil {
		reopened.Close()
		t.Fatal("missing records file was accepted")
	}
}

func TestOpeningDataDirWithDifferentScopeIsRejected(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateRun(); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(dir, "nested.example.com"); err == nil {
		t.Fatal("data directory was reused under a different scope root")
	}
}

func TestRefuseSymlinkedDataDir(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "target")
	if err := os.MkdirAll(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(base, "link")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(filepath.Join(base, "link")); err == nil {
		t.Fatal("symlinked data dir accepted")
	}
}

func TestRefuseSymlinkInsideRunsDir(t *testing.T) {
	s := newTestStore(t)
	evil := filepath.Join(t.TempDir(), "evil")
	if err := os.MkdirAll(evil, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(evil, filepath.Join(s.Dir(), "runs", "r20261106000000-deadbeef")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := s.Run("r20261106000000-deadbeef"); err == nil {
		t.Fatal("symlinked run dir resolved; expected refusal")
	}
}

func TestRefuseSymlinkedRecordsFileOnLoad(t *testing.T) {
	dir := t.TempDir()
	s, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "external.jsonl")
	if err := os.WriteFile(external, []byte("{}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(run.Path()); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(external, run.Path()); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := Open(dir, "example.com"); err == nil {
		t.Fatal("symlinked records file was followed during load")
	}
}

func TestMaterializeWorkFileGuards(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.MaterializeWorkFile("../escape.txt", []byte("x")); err == nil {
		t.Fatal("traversal accepted")
	}
	if _, err := s.MaterializeWorkFile("not-wordlist-name.txt", []byte("x")); err == nil {
		t.Fatal("unexpected prefix accepted")
	}
	p, err := s.MaterializeWorkFile("wordlist-preset-small.txt", []byte("www\napi\n"))
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(p)
	if err != nil || string(data) != "www\napi\n" {
		t.Fatalf("work file content %q err %v", data, err)
	}
}

func TestResolveRunLatest(t *testing.T) {
	s := newTestStore(t)
	first, _ := s.CreateRun()
	second, _ := s.CreateRun()
	got, err := s.ResolveRun("")
	if err != nil {
		t.Fatal(err)
	}
	if got.ID != second.ID {
		t.Fatalf("latest = %q, want %q", got.ID, second.ID)
	}
	got, err = s.ResolveRun(first.ID)
	if err != nil || got.ID != first.ID {
		t.Fatalf("ResolveRun(first) = %q, %v", got.ID, err)
	}
	if _, err := s.ResolveRun("r19990101000000-00000000"); err == nil {
		t.Fatal("unknown run accepted")
	}
}
