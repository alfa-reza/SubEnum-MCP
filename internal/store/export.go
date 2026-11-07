package store

import (
	"bytes"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// Export formats.
const (
	FormatJSONL = "jsonl"
	FormatCSV   = "csv"
)

// MaxExportRows caps a single export.
const MaxExportRows = 100000

// MaxExportBytes caps the encoded size of a single export.
const MaxExportBytes = 64 << 20

type ExportResult struct {
	RunID     string    `json:"run_id"`
	Folder    string    `json:"folder"`
	Format    string    `json:"format"`
	Path      string    `json:"path"`     // relative to the managed data dir
	PathAbs   string    `json:"path_abs"` // absolute path inside the managed data dir
	Manifest  string    `json:"manifest_path"`
	Rows      int       `json:"rows"`
	Bytes     int64     `json:"bytes"`
	SHA256    string    `json:"sha256"`
	CreatedAt time.Time `json:"created_at"`
}

type Manifest struct {
	RunID     string    `json:"run_id"`
	Folder    string    `json:"folder"`
	Format    string    `json:"format"`
	Rows      int       `json:"rows"`
	Bytes     int64     `json:"bytes"`
	SHA256    string    `json:"sha256"`
	ScopeRoot string    `json:"scope_root,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

// Export writes only in-scope records of the run to a folder inside the
// managed exports directory. Arbitrary destination paths are never accepted.
func (s *Store) Export(run *Run, format, folder, scopeRoot string) (*ExportResult, error) {
	switch format {
	case FormatJSONL, FormatCSV:
	default:
		return nil, fmt.Errorf("unsupported export format %q; use %q or %q", format, FormatJSONL, FormatCSV)
	}
	if err := SafeName(folder); err != nil {
		return nil, fmt.Errorf("invalid export folder: %w", err)
	}
	records := run.InScope("")
	if len(records) > MaxExportRows {
		return nil, fmt.Errorf("run %s has %d in-scope records; export cap is %d rows", run.ID, len(records), MaxExportRows)
	}
	targetDir, err := s.safePath("exports", folder)
	if err != nil {
		return nil, err
	}
	if err := ensureRootDir(s.root, filepath.Join("exports", folder)); err != nil {
		return nil, err
	}
	filename := "results.jsonl"
	if format == FormatCSV {
		filename = "results.csv"
	}
	target := filepath.Join(targetDir, filename)

	var buf exportBuffer
	if format == FormatCSV {
		if err := writeCSV(&buf, records); err != nil {
			return nil, err
		}
	} else {
		if err := writeJSONL(&buf, records); err != nil {
			return nil, err
		}
	}
	f, err := rootOpenFile(s.root, filepath.Join("exports", folder, filename), os.O_CREATE|os.O_WRONLY|os.O_EXCL)
	if err != nil {
		if os.IsExist(err) {
			return nil, fmt.Errorf("export %s already exists; choose another folder (for example append a date)", target)
		}
		return nil, err
	}
	data := buf.Bytes()
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		if removeErr := s.root.Remove(filepath.Join("exports", folder, filename)); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, fmt.Errorf("export write failed: %w (cleanup failed: %v)", firstError(writeErr, closeErr), removeErr)
		}
		return nil, firstError(writeErr, closeErr)
	}
	sum := sha256.Sum256(data)
	res := &ExportResult{
		RunID:     run.ID,
		Folder:    folder,
		Format:    format,
		Path:      "exports/" + folder + "/" + filename,
		PathAbs:   target,
		Rows:      len(records),
		Bytes:     int64(len(data)),
		SHA256:    hex.EncodeToString(sum[:]),
		CreatedAt: time.Now().UTC(),
	}
	man := Manifest{
		RunID: run.ID, Folder: folder, Format: format,
		Rows: res.Rows, Bytes: res.Bytes, SHA256: res.SHA256,
		ScopeRoot: scopeRoot, CreatedAt: res.CreatedAt,
	}
	if err := writeManifest(s.root, folder, &man); err != nil {
		if removeErr := s.root.Remove(filepath.Join("exports", folder, filename)); removeErr != nil && !os.IsNotExist(removeErr) {
			return nil, fmt.Errorf("write export manifest: %w (cleanup failed: %v)", err, removeErr)
		}
		return nil, err
	}
	res.Manifest = "exports/" + folder + "/manifest.json"
	return res, nil
}

type exportBuffer struct {
	bytes.Buffer
}

func (b *exportBuffer) Write(p []byte) (int, error) {
	if int64(b.Len())+int64(len(p)) > MaxExportBytes {
		return 0, fmt.Errorf("export exceeds byte cap of %d bytes", MaxExportBytes)
	}
	return b.Buffer.Write(p)
}

func firstError(writeErr, closeErr error) error {
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

func writeJSONL(w io.Writer, records []*model.Record) error {
	enc := json.NewEncoder(w)
	for _, rec := range records {
		if err := enc.Encode(rec); err != nil {
			return err
		}
	}
	return nil
}

var csvHeader = []string{
	"run_id", "host", "status", "provenance", "fixture_dns_records",
	"observed_at", "in_scope", "drop_reason", "notes",
}

// writeCSV applies formula-injection defense to every string cell: values
// starting with = + - @ or a tab/CR are prefixed with a single quote.
func writeCSV(w io.Writer, records []*model.Record) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(sanitizeCells(csvHeader)); err != nil {
		return err
	}
	for _, rec := range records {
		prov, err := json.Marshal(rec.Provenance)
		if err != nil {
			return err
		}
		var fixtureDNS []byte
		if len(rec.FixtureDNSRecords) > 0 {
			fixtureDNS, err = json.Marshal(rec.FixtureDNSRecords)
			if err != nil {
				return err
			}
		}
		row := sanitizeCells([]string{
			rec.RunID,
			rec.Host,
			string(rec.Status),
			string(prov),
			string(fixtureDNS),
			rec.ObservedAt.UTC().Format(time.RFC3339Nano),
			fmt.Sprintf("%t", rec.InScope),
			rec.DropReason,
			rec.Notes,
		})
		if err := cw.Write(row); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}

func sanitizeCells(row []string) []string {
	out := make([]string, len(row))
	for i, cell := range row {
		out[i] = SanitizeCSVCell(cell)
	}
	return out
}

// SanitizeCSVCell neutralizes spreadsheet formula interpretation.
func SanitizeCSVCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	return s
}

func writeManifest(root *os.Root, folder string, man *Manifest) error {
	rel := filepath.Join("exports", folder, "manifest.json")
	data, err := json.MarshalIndent(man, "", "  ")
	if err != nil {
		return err
	}
	f, err := rootOpenFile(root, rel, os.O_CREATE|os.O_WRONLY|os.O_EXCL)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("export %s already exists; choose another folder", filepath.Dir(rel))
		}
		return err
	}
	data = append(data, '\n')
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		if removeErr := root.Remove(rel); removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("write manifest failed: %w (cleanup failed: %v)", firstError(writeErr, closeErr), removeErr)
		}
		return firstError(writeErr, closeErr)
	}
	return nil
}
