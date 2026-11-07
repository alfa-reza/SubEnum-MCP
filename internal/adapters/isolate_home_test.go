package adapters

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestExecRunnerIsolatesAlterXHome(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("pinned external binaries target Linux amd64")
	}
	parentHome := t.TempDir()
	parentTemp := t.TempDir()
	t.Setenv("HOME", parentHome)
	t.Setenv("TMPDIR", parentTemp)
	t.Setenv("TMP", parentTemp)
	t.Setenv("TEMP", parentTemp)

	helper := filepath.Join(t.TempDir(), "write-alterx-config")
	script := "#!/bin/sh\nset -eu\nconfig=\"$HOME/.config/alterx/permutation_test.yaml\"\nmkdir -p \"$(dirname \"$config\")\"\nprintf 'temporary config' > \"$config\"\nprintf 'temporary output' > \"$TMPDIR/alterx-temp-check\"\nprintf '%s\\n%s\\n' \"$HOME\" \"$TMPDIR\"\n"
	if err := os.WriteFile(helper, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}

	stdout, _, err := (ExecRunner{}).Run(context.Background(), ExecSpec{
		Binary: helper, Timeout: 5 * time.Second, IsolateHome: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	paths := strings.Split(strings.TrimSpace(string(stdout)), "\n")
	if len(paths) != 2 {
		t.Fatalf("helper output = %q, want isolated home and temp directory", stdout)
	}
	isolatedHome, isolatedTemp := paths[0], paths[1]
	if isolatedHome == "" || isolatedHome == parentHome {
		t.Fatalf("helper used non-isolated home %q (parent home %q)", isolatedHome, parentHome)
	}
	if !strings.HasPrefix(isolatedTemp, isolatedHome+string(os.PathSeparator)) || isolatedTemp == parentTemp {
		t.Fatalf("helper used non-isolated temp directory %q (home %q, parent temp %q)", isolatedTemp, isolatedHome, parentTemp)
	}
	if _, err := os.Stat(filepath.Join(parentHome, ".config", "alterx", "permutation_test.yaml")); !os.IsNotExist(err) {
		t.Fatalf("external runner wrote AlterX config into user home: stat err=%v", err)
	}
	if _, err := os.Stat(isolatedHome); !os.IsNotExist(err) {
		t.Fatalf("temporary isolated home was not removed after process exit: %v", err)
	}
	if _, err := os.Stat(filepath.Join(isolatedTemp, "alterx-temp-check")); !os.IsNotExist(err) {
		t.Fatalf("temporary AlterX output was not removed: %v", err)
	}
}

func TestAlterXBuilderRequestsHomeIsolation(t *testing.T) {
	builder := NewBuilder("example.com", "", "", "/pinned/alterx")
	spec, err := builder.BuildAlterXCandidates([]string{"api.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if !spec.IsolateHome {
		t.Fatal("AlterX command spec did not request an isolated home")
	}
}
