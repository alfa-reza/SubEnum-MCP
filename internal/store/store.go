// Package store persists enumeration runs and artifacts under a managed
// data directory with path traversal and symlink protections.
package store

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

// Caps enforced by the store layer.
const (
	MaxRecordsPerRun = 20000
	MaxRuns          = 256
)

var (
	nameRE  = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,63}$`)
	runIDRE = regexp.MustCompile(`^r[0-9]{14}-[a-z0-9]{8}$`)
)

// SafeName validates a relative path component supplied from outside
// (run ids from tool input, export folder names).
func SafeName(name string) error {
	if name == "" {
		return fmt.Errorf("name must not be empty")
	}
	if strings.Contains(name, "/") || strings.Contains(name, "\\") ||
		name == "." || name == ".." || strings.Contains(name, "..") {
		return fmt.Errorf("name %q must be a single path component without '..' or separators", name)
	}
	if !nameRE.MatchString(name) {
		return fmt.Errorf("name %q must match %s", name, nameRE.String())
	}
	return nil
}

func SafeRunID(runID string) error {
	if runID == "" {
		return fmt.Errorf("run_id is empty; omit it to use the latest run, or list a valid run id")
	}
	if !runIDRE.MatchString(runID) {
		return fmt.Errorf("run_id %q is not a valid run id (expected format rYYYYMMDDhhmmss-xxxxxxxx like the ones returned by discovery tools)", runID)
	}
	return nil
}

var symlinked = errors.New("refusing to operate through a symlink")

// Store owns the managed data directory.
type Store struct {
	dir       string
	scopeRoot string
	root      *os.Root

	mu    sync.Mutex
	runs  map[string]*Run
	order []string
}

type Run struct {
	ID        string
	CreatedAt time.Time
	ScopeRoot string
	// Fixture is the persisted mode; ModeKnown is true when the record has
	// one. Legacy runs before this field have ModeKnown=false.
	Fixture   bool
	ModeKnown bool

	mu      sync.Mutex
	records map[string]*model.Record
	path    string
	rel     string
	root    *os.Root
}

type runMetadata struct {
	RunID     string    `json:"run_id"`
	ScopeRoot string    `json:"scope_root"`
	CreatedAt time.Time `json:"created_at"`
	// Fixture is nil in run metadata written before mode persistence; those
	// runs are legacy runs whose mode is inferred from recorded provenance.
	Fixture *bool `json:"fixture,omitempty"`
}

func Open(dir string, root ...string) (*Store, error) {
	if len(root) > 1 {
		return nil, fmt.Errorf("Open accepts at most one scope root")
	}
	scopeRoot := ""
	if len(root) == 1 {
		scopeRoot = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(root[0]), "."))
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	if fi, err := os.Lstat(abs); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return nil, fmt.Errorf("%w: data dir %s is a symlink", symlinked, abs)
		}
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(abs, 0o700); err != nil {
		return nil, err
	}
	rootDir, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	openedInfo, err := rootDir.Stat(".")
	if err != nil {
		rootDir.Close()
		return nil, err
	}
	pathInfo, err := os.Lstat(abs)
	if err != nil || pathInfo.Mode()&os.ModeSymlink != 0 || !os.SameFile(openedInfo, pathInfo) {
		rootDir.Close()
		if err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("%w: data dir %s changed while opening", symlinked, abs)
	}
	if err := restrictPrivateDirectory(rootDir, "."); err != nil {
		rootDir.Close()
		return nil, fmt.Errorf("restrict data directory permissions: %w", err)
	}
	for _, sub := range []string{"runs", "exports", "work"} {
		if err := ensureRootDir(rootDir, sub); err != nil {
			rootDir.Close()
			return nil, err
		}
	}
	s := &Store{dir: abs, scopeRoot: scopeRoot, root: rootDir, runs: map[string]*Run{}}
	if err := s.load(); err != nil {
		rootDir.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) Dir() string { return s.dir }

// Close releases the managed-root handle. Runs obtained from the store must no
// longer be used after Close.
func (s *Store) Close() error { return s.root.Close() }

// ProbeWrite checks that the opened managed root is writable without resolving
// the configured path again. The uniquely named probe is always removed.
func (s *Store) ProbeWrite() error {
	for attempt := 0; attempt < 8; attempt++ {
		name := "doctor-write-probe-" + randSuffix()
		f, err := rootOpenFile(s.root, name, os.O_CREATE|os.O_WRONLY|os.O_EXCL)
		if os.IsExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		payload := []byte("ok")
		n, writeErr := f.Write(payload)
		if writeErr == nil && n != len(payload) {
			writeErr = io.ErrShortWrite
		}
		closeErr := f.Close()
		removeErr := s.root.Remove(name)
		if writeErr != nil || closeErr != nil {
			cause := firstError(writeErr, closeErr)
			if removeErr != nil && !os.IsNotExist(removeErr) {
				return fmt.Errorf("write/close probe: %w (remove probe failed: %v)", cause, removeErr)
			}
			return fmt.Errorf("write/close probe: %w", cause)
		}
		if removeErr != nil && !os.IsNotExist(removeErr) {
			return fmt.Errorf("remove probe: %w", removeErr)
		}
		return nil
	}
	return fmt.Errorf("could not allocate a unique write probe after 8 attempts")
}

func (s *Store) load() error {
	entries, err := rootReadDir(s.root, "runs")
	if err != nil {
		return err
	}
	for _, e := range entries {
		if !e.IsDir() || !runIDRE.MatchString(e.Name()) {
			continue
		}
		runDir, err := s.safePath("runs", e.Name())
		if err != nil {
			return err
		}
		metaFile, err := rootOpenFile(s.root, filepath.Join("runs", e.Name(), "meta.json"), os.O_RDONLY)
		if err != nil {
			return fmt.Errorf("run %s has no safe scope metadata; use a fresh data directory: %w", e.Name(), err)
		}
		var meta runMetadata
		decodeErr := json.NewDecoder(metaFile).Decode(&meta)
		closeErr := metaFile.Close()
		if decodeErr != nil {
			return fmt.Errorf("run %s has invalid scope metadata: %w", e.Name(), decodeErr)
		}
		if closeErr != nil {
			return closeErr
		}
		storedRoot := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(meta.ScopeRoot), "."))
		if meta.RunID != e.Name() || storedRoot != s.scopeRoot {
			return fmt.Errorf("run %s is bound to scope root %q, but server data directory is opened for %q; use a separate data directory per root", e.Name(), storedRoot, s.scopeRoot)
		}
		run := &Run{ID: e.Name(), CreatedAt: meta.CreatedAt, ScopeRoot: storedRoot, ModeKnown: meta.Fixture != nil, Fixture: meta.Fixture != nil && *meta.Fixture, records: map[string]*model.Record{}, path: filepath.Join(runDir, "records.jsonl"), rel: filepath.Join("runs", e.Name(), "records.jsonl"), root: s.root}
		ct, err := runTimeFromID(e.Name())
		if err != nil {
			continue
		}
		if run.CreatedAt.IsZero() {
			run.CreatedAt = ct
		}
		if err := run.loadFile(); err != nil {
			return fmt.Errorf("loading run %s: %w", e.Name(), err)
		}
		s.runs[e.Name()] = run
		s.order = append(s.order, e.Name())
	}
	sort.Slice(s.order, func(i, j int) bool {
		a, b := s.runs[s.order[i]], s.runs[s.order[j]]
		if a.CreatedAt.Equal(b.CreatedAt) {
			return a.ID < b.ID
		}
		return a.CreatedAt.Before(b.CreatedAt)
	})
	return nil
}

// SetMode persists the fixture/real mode of a run. Used to adopt legacy runs
// that predate mode persistence; the run must still be empty at that point.
// droppedEmptyLocked reports whether there are no out-of-scope records;
// r.mu must be held.
func (r *Run) droppedEmptyLocked() bool {
	for _, rec := range r.records {
		if !rec.InScope {
			return false
		}
	}
	return true
}

func (r *Run) SetMode(fixture bool) error {
	r.mu.Lock()
	if len(r.records) != 0 || !r.droppedEmptyLocked() {
		r.mu.Unlock()
		return fmt.Errorf("run %s already has records; its legacy mode cannot be persisted", r.ID)
	}
	r.mu.Unlock()
	metaPath := strings.TrimSuffix(r.rel, "records.jsonl") + "meta.json"
	b, err := rootReadFile(r.root, metaPath)
	if err != nil {
		return fmt.Errorf("read run metadata: %w", err)
	}
	var meta runMetadata
	if err := json.Unmarshal(b, &meta); err != nil {
		return fmt.Errorf("run %s metadata is not valid JSON: %w", r.ID, err)
	}
	if meta.RunID != r.ID {
		return fmt.Errorf("run %s metadata run_id mismatch", r.ID)
	}
	if meta.Fixture != nil {
		return fmt.Errorf("run %s already has a persisted mode", r.ID)
	}
	meta.Fixture = boolPtr(fixture)
	out, err := json.Marshal(meta)
	if err != nil {
		return err
	}
	out = append(out, '\n')
	f, err := rootOpenFile(r.root, metaPath, os.O_WRONLY|os.O_TRUNC)
	if err != nil {
		return fmt.Errorf("open run metadata for mode adoption: %w", err)
	}
	if _, writeErr := f.Write(out); writeErr != nil {
		f.Close()
		return fmt.Errorf("write run metadata: %w", writeErr)
	}
	if closeErr := f.Close(); closeErr != nil {
		return fmt.Errorf("close run metadata: %w", closeErr)
	}
	r.Fixture = fixture
	r.ModeKnown = true
	return nil
}

func boolPtr(v bool) *bool { return &v }

func runTimeFromID(id string) (time.Time, error) {
	// id = r + YYYYMMDDhhmmss + "-" + rand8
	stamp := strings.SplitN(id[1:], "-", 2)[0]
	return time.Parse("20060102150405", stamp)
}

// safePath retains the historical absolute-path API while checking relative
// components through os.Root. os.Root confines escape even when platform path
// protection differs.
func (s *Store) safePath(rel ...string) (string, error) {
	name, err := rootRel(rel...)
	if err != nil {
		return "", err
	}
	if err := checkRootPath(s.root, name); err != nil {
		return "", err
	}
	parts := append([]string{s.dir}, rel...)
	return filepath.Join(parts...), nil
}

func ensureRootDir(root *os.Root, rel string) error {
	if err := checkRootPath(root, rel); err != nil && !os.IsNotExist(err) {
		return err
	}
	if err := root.MkdirAll(rel, 0o700); err != nil {
		return err
	}
	if err := restrictPrivateDirectory(root, rel); err != nil {
		return err
	}
	return checkRootPath(root, rel)
}

// CreateRun creates a new run and its backing file. The mode is persisted so
// later access from the other fixture/real mode is rejected.
func (s *Store) CreateRun(fixture bool) (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.runs) >= MaxRuns {
		return nil, fmt.Errorf("run cap of %d reached in %s; archive or clean old runs before starting a new one", MaxRuns, s.dir)
	}
	now := time.Now().UTC()
	var id, relRun string
	created := false
	for attempt := 0; attempt < 8; attempt++ {
		id = now.Format("r20060102150405") + "-" + randSuffix()
		if _, ok := s.runs[id]; ok {
			continue
		}
		relRun = filepath.Join("runs", id)
		if err := s.root.Mkdir(relRun, 0o700); err != nil {
			if os.IsExist(err) {
				continue
			}
			return nil, err
		}
		created = true
		break
	}
	if !created {
		return nil, fmt.Errorf("could not allocate a unique run directory after 8 attempts")
	}
	cleanup := func(cause error) error {
		if err := s.root.RemoveAll(relRun); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("%w (cleanup of new run directory failed: %v)", cause, err)
		}
		return cause
	}
	runDir := filepath.Join(s.dir, relRun)
	relRec := filepath.Join(relRun, "records.jsonl")
	recPath := filepath.Join(runDir, "records.jsonl")
	f, err := rootOpenFile(s.root, relRec, os.O_CREATE|os.O_WRONLY|os.O_EXCL)
	if err != nil {
		return nil, cleanup(err)
	}
	if err := f.Close(); err != nil {
		return nil, cleanup(err)
	}
	run := &Run{ID: id, CreatedAt: now, ScopeRoot: s.scopeRoot, ModeKnown: true, Fixture: fixture, records: map[string]*model.Record{}, path: recPath, rel: relRec, root: s.root}
	metaBytes, err := json.Marshal(runMetadata{RunID: id, ScopeRoot: s.scopeRoot, CreatedAt: now, Fixture: boolPtr(fixture)})
	if err != nil {
		return nil, cleanup(err)
	}
	metaFile, err := rootOpenFile(s.root, filepath.Join(relRun, "meta.json"), os.O_CREATE|os.O_WRONLY|os.O_EXCL)
	if err != nil {
		return nil, cleanup(err)
	}
	metaBytes = append(metaBytes, '\n')
	n, writeErr := metaFile.Write(metaBytes)
	if writeErr == nil && n != len(metaBytes) {
		writeErr = io.ErrShortWrite
	}
	closeErr := metaFile.Close()
	if writeErr != nil {
		return nil, cleanup(writeErr)
	}
	if closeErr != nil {
		return nil, cleanup(closeErr)
	}
	s.runs[id] = run
	s.order = append(s.order, id)
	return run, nil
}

func (s *Store) Run(id string) (*Run, error) {
	if err := SafeRunID(id); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	run, ok := s.runs[id]
	if !ok {
		return nil, fmt.Errorf("run %q not found in %s; call a discovery tool without run_id to start a new run", id, s.dir)
	}
	return run, nil
}

// LatestRun returns the most recently created run.
func (s *Store) LatestRun() (*Run, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.order) == 0 {
		return nil, fmt.Errorf("no runs recorded yet; start with discover_subdomains or resolve_hosts")
	}
	return s.runs[s.order[len(s.order)-1]], nil
}

// ResolveRun returns runID if set, otherwise the latest run.
func (s *Store) ResolveRun(runID string) (*Run, error) {
	if runID == "" {
		return s.LatestRun()
	}
	return s.Run(runID)
}

// Runs lists run ids oldest first.
func (s *Store) Runs() []*Run {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*Run, 0, len(s.order))
	for _, id := range s.order {
		out = append(out, s.runs[id])
	}
	return out
}

func (r *Run) loadFile() error {
	f, err := rootOpenFile(r.root, r.rel, os.O_RDONLY)
	if err != nil {
		return fmt.Errorf("open records for run %s: %w", r.ID, err)
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var rec model.Record
		if err := json.Unmarshal(line, &rec); err != nil {
			return fmt.Errorf("corrupt record in %s: %w", r.path, err)
		}
		if rec.RunID != r.ID {
			return fmt.Errorf("corrupt record in %s: record run_id %q does not match run %q", r.path, rec.RunID, r.ID)
		}
		if rec.Host == "" || !rec.Status.Valid() {
			return fmt.Errorf("corrupt record in %s: empty host or invalid status %q", r.path, rec.Status)
		}
		if rec.InScope && r.ScopeRoot != "" {
			sc, err := scope.New(r.ScopeRoot, scope.DefaultPolicy())
			if err != nil {
				return fmt.Errorf("invalid run scope root %q: %w", r.ScopeRoot, err)
			}
			classified := sc.Classify(rec.Host)
			if !classified.InScope || classified.Normalized != rec.Host {
				return fmt.Errorf("corrupt record in %s: in-scope host %q is invalid for root %q", r.path, rec.Host, r.ScopeRoot)
			}
		}
		r.records[recordKey(&rec)] = &rec
	}
	return sc.Err()
}

// Upsert merges rec into the run by host, appending a full snapshot line for
// audit (later lines win when reloading).
func (r *Run) Upsert(rec *model.Record) (*model.Record, error) {
	if rec == nil || rec.Host == "" {
		return nil, fmt.Errorf("record must have a host")
	}
	if rec.RunID != r.ID {
		return nil, fmt.Errorf("record run_id %q does not match target run %q", rec.RunID, r.ID)
	}
	if !rec.Status.Valid() {
		return nil, fmt.Errorf("invalid status %q for host %s", rec.Status, rec.Host)
	}
	if rec.InScope && r.ScopeRoot != "" {
		sc, err := scope.New(r.ScopeRoot, scope.DefaultPolicy())
		if err != nil {
			return nil, fmt.Errorf("invalid run scope root %q: %w", r.ScopeRoot, err)
		}
		classified := sc.Classify(rec.Host)
		if !classified.InScope {
			return nil, fmt.Errorf("refusing to store host %q as in-scope for root %q: %s", rec.Host, r.ScopeRoot, classified.Reason)
		}
		rec.Host = classified.Normalized
	}
	key := recordKey(rec)
	r.mu.Lock()
	defer r.mu.Unlock()
	candidate := cloneRecord(rec)
	if len(r.records) >= MaxRecordsPerRun {
		if _, exists := r.records[key]; !exists {
			return nil, fmt.Errorf("run %s reached the %d record cap; start a new run or raise the cap", r.ID, MaxRecordsPerRun)
		}
	}
	if existing, ok := r.records[key]; ok {
		candidate = cloneRecord(existing)
		model.Merge(candidate, rec)
	}
	if err := r.append(candidate); err != nil {
		return nil, err
	}
	r.records[key] = candidate
	return cloneRecord(candidate), nil
}

// recordKey keeps rejected intake entries in a separate namespace so a
// truncated or sanitized rejected hostname cannot overwrite an in-scope host.
func recordKey(rec *model.Record) string {
	if rec.InScope {
		return rec.Host
	}
	return "\x00dropped:" + rec.Host + "\x00" + rec.DropReason
}

func cloneRecord(rec *model.Record) *model.Record {
	if rec == nil {
		return nil
	}
	copy := *rec
	copy.Provenance = append([]model.Provenance(nil), rec.Provenance...)
	if rec.FixtureDNSRecords != nil {
		copy.FixtureDNSRecords = make(model.DNSRecords, len(rec.FixtureDNSRecords))
		for rrType, values := range rec.FixtureDNSRecords {
			copy.FixtureDNSRecords[rrType] = append([]string(nil), values...)
		}
	}
	if rec.ObservedDNSRecords != nil {
		copy.ObservedDNSRecords = make(model.DNSRecords, len(rec.ObservedDNSRecords))
		for rrType, values := range rec.ObservedDNSRecords {
			copy.ObservedDNSRecords[rrType] = append([]string(nil), values...)
		}
	}
	return &copy
}

func (r *Run) append(rec *model.Record) error {
	f, err := rootOpenFile(r.root, r.rel, os.O_WRONLY|os.O_APPEND)
	if err != nil {
		return err
	}
	data, err := json.Marshal(rec)
	if err != nil {
		_ = f.Close()
		return err
	}
	data = append(data, '\n')
	n, writeErr := f.Write(data)
	if writeErr == nil && n != len(data) {
		writeErr = io.ErrShortWrite
	}
	closeErr := f.Close()
	if writeErr != nil {
		return writeErr
	}
	return closeErr
}

// Get returns a copy of the record for host, if present.
func (r *Run) Get(host string) (model.Record, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	rec, ok := r.records[host]
	if !ok {
		return model.Record{}, false
	}
	return *cloneRecord(rec), true
}

// All returns every record sorted by host.
func (r *Run) All() []*model.Record {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := make([]*model.Record, 0, len(r.records))
	for _, rec := range r.records {
		out = append(out, cloneRecord(rec))
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out
}

// InScope returns in-scope records sorted by host, optionally filtered by
// status. Scope filtering happens here (handoff/pagination/export path).
func (r *Run) InScope(status model.Status) []*model.Record {
	out := make([]*model.Record, 0)
	var sc *scope.Scope
	if r.ScopeRoot != "" {
		if parsed, err := scope.New(r.ScopeRoot, scope.DefaultPolicy()); err == nil {
			sc = parsed
		}
	}
	for _, rec := range r.All() {
		if !rec.InScope {
			continue
		}
		if sc != nil {
			classified := sc.Classify(rec.Host)
			if !classified.InScope {
				continue
			}
			if classified.Normalized != rec.Host {
				copy := *rec
				copy.Host = classified.Normalized
				rec = &copy
			}
		}
		if status != "" && rec.Status != status {
			continue
		}
		out = append(out, rec)
	}
	return out
}

// Dropped returns out-of-scope intake records that were rejected with reasons.
func (r *Run) Dropped() []*model.Record {
	out := make([]*model.Record, 0)
	for _, rec := range r.All() {
		if !rec.InScope {
			out = append(out, rec)
		}
	}
	return out
}

func (r *Run) Count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.records)
}

// Path returns the backing records file path (managed dir only).
func (r *Run) Path() string { return r.path }

// MaterializeWorkFile writes content into the managed work directory under a
// validated name and returns the absolute path. Only ever used for internal
// artifacts such as materialized preset wordlists.
func (s *Store) MaterializeWorkFile(name string, content []byte) (string, error) {
	if err := SafeName(strings.TrimPrefix(strings.TrimSuffix(name, ".txt"), "wordlist-")); err != nil {
		return "", fmt.Errorf("invalid work file name %q: %w", name, err)
	}
	if strings.Contains(name, "/") || strings.Contains(name, "..") || !strings.HasPrefix(name, "wordlist-") || !strings.HasSuffix(name, ".txt") {
		return "", fmt.Errorf("work file %q must live in the managed work folder as wordlist-*.txt", name)
	}
	dir, err := s.safePath("work")
	if err != nil {
		return "", err
	}
	if err := ensureRootDir(s.root, "work"); err != nil {
		return "", err
	}
	var targetRel string
	var f *os.File
	for attempt := 0; attempt < 8; attempt++ {
		fileName := strings.TrimSuffix(name, ".txt") + "-" + randSuffix() + ".txt"
		targetRel = filepath.Join("work", fileName)
		f, err = rootOpenFile(s.root, targetRel, os.O_CREATE|os.O_WRONLY|os.O_EXCL)
		if err == nil {
			break
		}
		if !os.IsExist(err) {
			return "", err
		}
	}
	if f == nil {
		return "", fmt.Errorf("could not allocate a unique work file after 8 attempts")
	}
	n, writeErr := f.Write(content)
	if writeErr == nil && n != len(content) {
		writeErr = io.ErrShortWrite
	}
	closeErr := f.Close()
	if writeErr != nil || closeErr != nil {
		if removeErr := s.root.Remove(targetRel); removeErr != nil && !os.IsNotExist(removeErr) {
			return "", fmt.Errorf("write work file failed: %w (cleanup failed: %v)", firstError(writeErr, closeErr), removeErr)
		}
		return "", firstError(writeErr, closeErr)
	}
	return filepath.Join(dir, filepath.Base(targetRel)), nil
}

// RemoveWorkFile removes only a generated wordlist file directly inside the
// managed work directory. Paths outside that directory are never accepted.
func (s *Store) RemoveWorkFile(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("work file path must be absolute")
	}
	workDir := filepath.Join(s.dir, "work")
	rel, err := filepath.Rel(workDir, filepath.Clean(path))
	if err != nil || rel == "." || rel == ".." || filepath.IsAbs(rel) ||
		strings.HasPrefix(rel, ".."+string(filepath.Separator)) || strings.Contains(rel, string(filepath.Separator)) {
		return fmt.Errorf("work file path must name one file directly inside %s", workDir)
	}
	if !strings.HasPrefix(rel, "wordlist-") || !strings.HasSuffix(rel, ".txt") || strings.Contains(rel, "..") {
		return fmt.Errorf("work file %q is not a generated wordlist", rel)
	}
	if err := SafeName(strings.TrimSuffix(strings.TrimPrefix(rel, "wordlist-"), ".txt")); err != nil {
		return fmt.Errorf("invalid work file name %q: %w", rel, err)
	}
	err = s.root.Remove(filepath.Join("work", rel))
	if os.IsNotExist(err) {
		return nil
	}
	return err
}
