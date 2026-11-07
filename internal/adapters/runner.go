// Package adapters defines external-process execution specs and typed
// command builders for Subfinder, dnsx and AlterX.
//
// Builders construct fixed argv arrays (never shell strings) and callers can
// only influence data payloads (stdin), never command-line flags. Execution
// is disabled unless the operator explicitly unlocks external mode.
package adapters

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// DefaultTimeout bounds a single external invocation.
const DefaultTimeout = 2 * time.Minute

// MaxOutputBytes caps captured stdout of an external call.
const MaxOutputBytes = 16 << 20 // 16 MiB

// ExecSpec is a fully constructed external command: bare argv plus an stdin
// data payload. No shell is ever involved.
type ExecSpec struct {
	Binary        string        `json:"binary"`
	PinnedBackend string        `json:"pinned_backend,omitempty"`
	Args          []string      `json:"args,omitempty"`
	Stdin         string        `json:"stdin,omitempty"`
	Timeout       time.Duration `json:"timeout_seconds,omitempty"`
	IsolateHome   bool          `json:"isolate_home,omitempty"`
	// Root is informational (audit), never passed as a flag by itself.
	Root string `json:"root,omitempty"`
}

func (e ExecSpec) Describe() string {
	return fmt.Sprintf("%s %s", e.Binary, strings.Join(e.Args, " "))
}

// Runner executes an ExecSpec. Implementations must not use a shell.
type Runner interface {
	Run(ctx context.Context, spec ExecSpec) (stdout, stderr []byte, err error)
}

// ExecRunner is the production runner. It is only wired when the operator
// has explicitly enabled and authorized external mode.
type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, spec ExecSpec) (stdout, stderr []byte, runErr error) {
	if spec.PinnedBackend != "" {
		if _, _, err := VerifyPinnedBinary(spec.PinnedBackend, spec.Binary); err != nil {
			return nil, nil, fmt.Errorf("refusing to execute unpinned external backend: %w", err)
		}
	}
	if spec.Timeout <= 0 {
		spec.Timeout = DefaultTimeout
	}
	runCtx, cancel := context.WithTimeout(ctx, spec.Timeout)
	defer cancel()
	cmd := exec.CommandContext(runCtx, spec.Binary, spec.Args...)
	if spec.IsolateHome {
		home, err := os.MkdirTemp("", "subenum-alterx-home-*")
		if err != nil {
			return nil, nil, fmt.Errorf("create isolated backend home: %w", err)
		}
		defer func() {
			if err := os.RemoveAll(home); err != nil && !os.IsNotExist(err) {
				if runErr == nil {
					runErr = fmt.Errorf("remove isolated backend home: %w", err)
				} else {
					runErr = fmt.Errorf("%w (remove isolated backend home: %v)", runErr, err)
				}
			}
		}()
		if err := os.Chmod(home, 0o700); err != nil {
			return nil, nil, fmt.Errorf("secure isolated backend home: %w", err)
		}
		tempDir := filepath.Join(home, "tmp")
		if err := os.Mkdir(tempDir, 0o700); err != nil {
			return nil, nil, fmt.Errorf("create isolated backend temp directory: %w", err)
		}
		cmd.Env = environmentWithIsolatedHome(os.Environ(), home, tempDir)
		cmd.Dir = home
	}
	if spec.Stdin != "" {
		cmd.Stdin = strings.NewReader(spec.Stdin)
	}
	var out, errBuf limitedBuffer
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	if err := cmd.Run(); err != nil {
		if runCtx.Err() == context.DeadlineExceeded {
			return out.Bytes(), errBuf.Bytes(), fmt.Errorf("%s timed out after %s; partial output may be available (stderr: %s): %w", spec.PinnedBackend, spec.Timeout, truncate(errBuf.String(), 512), context.DeadlineExceeded)
		}
		if ctx.Err() != nil {
			return out.Bytes(), errBuf.Bytes(), fmt.Errorf("%s interrupted: %w", spec.PinnedBackend, ctx.Err())
		}
		return out.Bytes(), errBuf.Bytes(), fmt.Errorf("external %q failed after %s: %w (stderr: %s)", spec.Binary, spec.Timeout, err, truncate(errBuf.String(), 512))
	}
	if out.overflow || errBuf.overflow {
		return out.Bytes(), errBuf.Bytes(), fmt.Errorf("external %q exceeded the %d-byte output hard cap", spec.Binary, MaxOutputBytes)
	}
	return out.Bytes(), errBuf.Bytes(), nil
}

func environmentWithIsolatedHome(parent []string, home, tempDir string) []string {
	filtered := make([]string, 0, len(parent)+10)
	for _, item := range parent {
		key, _, ok := strings.Cut(item, "=")
		if ok && (strings.EqualFold(key, "HOME") || strings.EqualFold(key, "USERPROFILE") ||
			strings.EqualFold(key, "XDG_CONFIG_HOME") || strings.EqualFold(key, "XDG_CACHE_HOME") ||
			strings.EqualFold(key, "XDG_DATA_HOME") || strings.EqualFold(key, "APPDATA") ||
			strings.EqualFold(key, "LOCALAPPDATA") || strings.EqualFold(key, "TMPDIR") ||
			strings.EqualFold(key, "TMP") || strings.EqualFold(key, "TEMP")) {
			continue
		}
		filtered = append(filtered, item)
	}
	return append(filtered,
		"HOME="+home,
		"USERPROFILE="+home,
		"XDG_CONFIG_HOME="+filepath.Join(home, ".config"),
		"XDG_CACHE_HOME="+filepath.Join(home, ".cache"),
		"XDG_DATA_HOME="+filepath.Join(home, ".local", "share"),
		"APPDATA="+filepath.Join(home, "AppData", "Roaming"),
		"LOCALAPPDATA="+filepath.Join(home, "AppData", "Local"),
		"TMPDIR="+tempDir,
		"TMP="+tempDir,
		"TEMP="+tempDir,
	)
}

// limitedBuffer caps captured output so a runaway backend cannot exhaust
// memory.
type limitedBuffer struct {
	buf      bytes.Buffer
	overflow bool
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	room := MaxOutputBytes - l.buf.Len()
	if room <= 0 {
		l.overflow = true
		return len(p), nil
	}
	if len(p) > room {
		l.buf.Write(p[:room])
		l.overflow = true
		return len(p), nil
	}
	return l.buf.Write(p)
}

func (l *limitedBuffer) Bytes() []byte { return l.buf.Bytes() }

func (l *limitedBuffer) String() string { return l.buf.String() }

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}

// FakeRunner records invocations and replans canned responses. It never
// spawns a process, which lets tests prove that fixture mode performs no
// subprocess execution.
type FakeRunner struct {
	mu        sync.Mutex
	Calls     []ExecSpec
	Fn        func(spec ExecSpec) (stdout []byte, stderr []byte, err error)
	FnContext func(ctx context.Context, spec ExecSpec) (stdout []byte, stderr []byte, err error)
}

func (f *FakeRunner) Run(ctx context.Context, spec ExecSpec) ([]byte, []byte, error) {
	f.mu.Lock()
	f.Calls = append(f.Calls, spec)
	fn := f.Fn
	fnContext := f.FnContext
	f.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, nil, err
	}
	if fnContext != nil {
		return fnContext(ctx, spec)
	}
	if fn == nil {
		return nil, nil, fmt.Errorf("fake runner: no canned response for %s", spec.Describe())
	}
	return fn(spec)
}

func (f *FakeRunner) CallCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.Calls)
}
