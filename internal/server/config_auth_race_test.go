package server

import (
	"os"
	"path/filepath"
	"testing"
)

func TestAuthorizationReaderRejectsFileReplacementAfterInspection(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	path := filepath.Join(dir, "authorization.json")
	if err := os.WriteFile(path, []byte(`{"authorized":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	inspected, err := root.Lstat("authorization.json")
	if err != nil {
		t.Fatal(err)
	}
	replacement := filepath.Join(dir, "replacement.json")
	if err := os.WriteFile(replacement, []byte(`{"authorized":false}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(replacement, path); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}

	if _, err := readAuthorizationDocument(root, "authorization.json", inspected); err == nil {
		t.Fatal("authorization reader accepted a file replaced by a symlink after inspection")
	}
}
