package store

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestOpenRestrictsExistingDataDirectoryModes(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows directory access is governed by ACLs, not Unix permission bits")
	}
	dir := filepath.Join(t.TempDir(), "data")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for _, sub := range []string{"runs", "exports", "work"} {
		if err := os.Mkdir(filepath.Join(dir, sub), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}

	s, err := Open(dir, "example.com")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	for _, path := range append([]string{dir}, []string{
		filepath.Join(dir, "runs"),
		filepath.Join(dir, "exports"),
		filepath.Join(dir, "work"),
	}...) {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if got := info.Mode().Perm(); got != 0o700 {
			t.Errorf("directory %s mode = %04o, want 0700", path, got)
		}
	}
}

func TestRemoveWorkFileOnlyRemovesManagedWordlists(t *testing.T) {
	s := newTestStore(t)
	managed, err := s.MaterializeWorkFile("wordlist-preset-small.txt", []byte("api\n"))
	if err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "wordlist-user.txt")
	if err := os.WriteFile(outside, []byte("preserve"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := s.RemoveWorkFile(outside); err == nil {
		t.Fatal("RemoveWorkFile accepted a path outside the managed work directory")
	}
	if _, err := os.Stat(outside); err != nil {
		t.Fatalf("outside file was changed or removed: %v", err)
	}
	if err := s.RemoveWorkFile(managed); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(managed); !os.IsNotExist(err) {
		t.Fatalf("managed wordlist remains after removal: %v", err)
	}
}
