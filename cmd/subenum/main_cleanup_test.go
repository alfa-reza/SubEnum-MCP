package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// TestMainCleanupHelper is selected only by the child process started below.
func TestMainCleanupHelper(t *testing.T) {}

func TestTestMainCleansBuildDirectoryBeforeExit(t *testing.T) {
	tempRoot := t.TempDir()
	t.Setenv("TMPDIR", tempRoot)
	t.Setenv("TMP", tempRoot)
	t.Setenv("TEMP", tempRoot)

	cmd := exec.Command(os.Args[0], "-test.run=^TestMainCleanupHelper$")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("child test process failed: %v\n%s", err, output)
	}
	entries, err := os.ReadDir(tempRoot)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), "subenum-smoke-") {
			t.Fatalf("TestMain leaked build directory %q before process exit", entry.Name())
		}
	}
}
