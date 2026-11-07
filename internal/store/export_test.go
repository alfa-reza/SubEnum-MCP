package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

func seededRun(t *testing.T, s *Store) *Run {
	t.Helper()
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	recs := []*model.Record{
		{
			RunID: run.ID, Host: "api.example.com", Status: model.StatusResolved,
			Provenance:        []model.Provenance{{Backend: "mock.dnsx", Method: model.MethodResolve, Fixture: true}},
			FixtureDNSRecords: model.DNSRecords{"A": {"203.0.113.10"}},
			InScope:           true,
		},
		{
			RunID: run.ID, Host: "www.example.com", Status: model.StatusNoAnswer,
			Provenance: []model.Provenance{{Backend: "mock.dnsx", Method: model.MethodBruteforce, Detail: "preset-small", Fixture: true}},
			InScope:    true,
			Notes:      model.NoteNoAnswerNotNXDOMAIN,
		},
		{
			RunID: run.ID, Host: "out.example.net", Status: model.StatusCandidate,
			Provenance: []model.Provenance{{Backend: "intake", Fixture: true}},
			InScope:    false, DropReason: "out_of_scope",
		},
	}
	for _, r := range recs {
		if _, err := run.Upsert(r); err != nil {
			t.Fatal(err)
		}
	}
	return run
}

func TestExportJSONL(t *testing.T) {
	s := newTestStore(t)
	run := seededRun(t, s)
	res, err := s.Export(run, FormatJSONL, "exp-jsonl", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	if res.Rows != 2 {
		t.Fatalf("rows = %d, want 2 (out-of-scope excluded)", res.Rows)
	}
	data, err := os.ReadFile(res.PathAbs)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != res.SHA256 {
		t.Fatal("checksum mismatch")
	}
	lines := strings.Split(strings.TrimSpace(string(data)), "\n")
	if len(lines) != 2 {
		t.Fatalf("jsonl lines = %d", len(lines))
	}
	var rec model.Record
	if err := json.Unmarshal([]byte(lines[0]), &rec); err != nil {
		t.Fatal(err)
	}
	if rec.Host != "api.example.com" {
		t.Fatalf("first record host = %q", rec.Host)
	}
	if strings.Contains(string(data), "out.example.net") {
		t.Fatal("out-of-scope record leaked into export")
	}
}

func TestExportCSVFormulaInjectionDefense(t *testing.T) {
	s := newTestStore(t)
	run, _ := s.CreateRun()
	payloads := []string{"=cmd|'/c calc'!A1", "+SUM(A1:A2)", "-1", "@SUM(1)", "\tTAB", "\rCR"}
	for i, p := range payloads {
		r := rec(run.ID, "x.example.com", "candidate", true, "")
		r.Host = "h" + string(rune('a'+i)) + ".example.com"
		r.Notes = p
		if _, err := run.Upsert(r); err != nil {
			t.Fatal(err)
		}
	}
	res, err := s.Export(run, FormatCSV, "exp-csv", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(res.PathAbs)
	if err != nil {
		t.Fatal(err)
	}
	rows, err := csv.NewReader(bytes.NewReader(data)).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1+len(payloads) {
		t.Fatalf("csv rows = %d, want %d (header+%d)", len(rows), 1+len(payloads), len(payloads))
	}
	notesCol := len(csvHeader) - 1
	for _, row := range rows[1:] {
		notes := row[notesCol]
		if strings.HasPrefix(notes, "=") || strings.HasPrefix(notes, "+") || strings.HasPrefix(notes, "-") ||
			strings.HasPrefix(notes, "@") || strings.HasPrefix(notes, "\t") || strings.HasPrefix(notes, "\r") {
			t.Fatalf("dangerous CSV cell not neutralized: %q", notes)
		}
		if !strings.HasPrefix(notes, "'") {
			t.Fatalf("sanitized cell missing quote prefix: %q", notes)
		}
	}
}

func TestExportRefusesTraversalAndExistingFolder(t *testing.T) {
	s := newTestStore(t)
	run := seededRun(t, s)
	if _, err := s.Export(run, FormatJSONL, "../escape", "example.com"); err == nil {
		t.Fatal("traversal folder accepted")
	}
	if _, err := s.Export(run, FormatJSONL, "sub/func", "example.com"); err == nil {
		t.Fatal("nested folder accepted")
	}
	if _, err := s.Export(run, "yaml", "exp-yaml", "example.com"); err == nil {
		t.Fatal("unknown format accepted")
	}
	if _, err := s.Export(run, FormatJSONL, "dup", "example.com"); err != nil {
		t.Fatalf("first export failed: %v", err)
	}
	if _, err := s.Export(run, FormatJSONL, "dup", "example.com"); err == nil {
		t.Fatal("overwrite of existing export accepted")
	}
}

func TestExportRefusesSymlinkedTargetFolder(t *testing.T) {
	s := newTestStore(t)
	run := seededRun(t, s)
	evilDir := t.TempDir()
	if err := os.Symlink(evilDir, filepath.Join(s.Dir(), "exports", "evil")); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if _, err := s.Export(run, FormatJSONL, "evil", "example.com"); err == nil {
		t.Fatal("symlinked export folder accepted")
	}
}

func TestExportRunHasNoRuns(t *testing.T) {
	s := newTestStore(t)
	if _, err := s.ResolveRun(""); err == nil {
		t.Fatal("expected error when no run exists")
	}
}

func TestSanitizeCSVCell(t *testing.T) {
	cases := map[string]string{
		"=1":          "'=1",
		"+2":          "'+2",
		"-3":          "'-3",
		"@x":          "'@x",
		"\ty":         "'\ty",
		"normal":      "normal",
		"":            "",
		"example.com": "example.com",
	}
	for in, want := range cases {
		if got := SanitizeCSVCell(in); got != want {
			t.Errorf("SanitizeCSVCell(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestExportManifestWritten(t *testing.T) {
	s := newTestStore(t)
	run := seededRun(t, s)
	res, err := s.Export(run, FormatCSV, "with-manifest", "example.com")
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(filepath.Dir(res.PathAbs), "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var man Manifest
	if err := json.Unmarshal(data, &man); err != nil {
		t.Fatal(err)
	}
	if man.Rows != res.Rows || man.SHA256 != res.SHA256 || man.Format != FormatCSV {
		t.Fatalf("manifest mismatch: %+v vs %+v", man, res)
	}
	if res.Manifest != "exports/with-manifest/manifest.json" {
		t.Fatalf("manifest_path = %q, want managed relative path", res.Manifest)
	}
}

func TestExportManifestFailureCleansCreatedDataFile(t *testing.T) {
	s := newTestStore(t)
	run := seededRun(t, s)
	folder := "manifest-conflict"
	targetDir := filepath.Join(s.Dir(), "exports", folder)
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	wantManifest := []byte("pre-existing manifest")
	if err := os.WriteFile(filepath.Join(targetDir, "manifest.json"), wantManifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Export(run, FormatJSONL, folder, "example.com"); err == nil {
		t.Fatal("export unexpectedly succeeded with an existing manifest")
	}
	if _, err := os.Lstat(filepath.Join(targetDir, "results.jsonl")); !os.IsNotExist(err) {
		t.Fatalf("failed export left a misleading results file, stat err=%v", err)
	}
	got, err := os.ReadFile(filepath.Join(targetDir, "manifest.json"))
	if err != nil || string(got) != string(wantManifest) {
		t.Fatalf("pre-existing manifest changed: got %q err=%v", got, err)
	}
}

func TestExportEnforcesByteCap(t *testing.T) {
	s := newTestStore(t)
	run, err := s.CreateRun()
	if err != nil {
		t.Fatal(err)
	}
	record := rec(run.ID, "large.example.com", "candidate", true, "")
	record.Notes = strings.Repeat("x", (64<<20)+1)
	run.records[recordKey(record)] = record
	if _, err := s.Export(run, FormatJSONL, "too-large", "example.com"); err == nil || !strings.Contains(err.Error(), "byte cap") {
		t.Fatalf("oversized export error = %v, want byte-cap refusal", err)
	}
}
