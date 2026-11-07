package adapters

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

func TestBuildSubfinderDiscoverArgv(t *testing.T) {
	b := NewBuilder("Example.com.", "/opt/tools/subfinder", "", "")
	spec, err := b.BuildSubfinderDiscover(scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	if spec.Binary != "/opt/tools/subfinder" {
		t.Fatalf("binary = %q", spec.Binary)
	}
	if spec.Args[0] != "-d" || spec.Args[1] != "example.com" {
		t.Fatalf("argv = %v", spec.Args)
	}
	for _, flag := range spec.Args {
		if strings.ContainsAny(flag, ";&|`$") {
			t.Fatalf("suspicious shell metacharacter in argv: %q", spec.Args)
		}
	}
}

func TestBuildSubfinderRejectsUnconfiguredBinary(t *testing.T) {
	b := NewBuilder("example.com", "", "", "")
	if _, err := b.BuildSubfinderDiscover(scope.DefaultPolicy()); err == nil {
		t.Fatal("expected error for unconfigured binary")
	}
}

func TestBuildSubfinderRejectsPlaceholderRoot(t *testing.T) {
	b := NewBuilder("example.com", "subfinder", "dnsx", "alterx")
	if _, err := b.BuildSubfinderDiscover(scope.DefaultPolicy()); err != nil {
		// placeholder roots are valid DNS names; builders do not block them
		// (the external gate is responsible for the refusal), so this must build.
		t.Fatalf("valid root rejected: %v", err)
	}
}

func TestBuildAlterXCandidatesStdin(t *testing.T) {
	b := NewBuilder("example.com", "", "unused", "/opt/tools/alterx")
	spec, err := b.BuildAlterXCandidates([]string{"API.Example.com.", "api.example.com", "dev-cdn.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	if spec.Binary != "/opt/tools/alterx" {
		t.Fatalf("binary = %q", spec.Binary)
	}
	lines := strings.Split(strings.TrimSpace(spec.Stdin), "\n")
	if len(lines) != 2 || lines[0] != "api.example.com" || lines[1] != "dev-cdn.example.com" {
		t.Fatalf("stdin hosts = %v (dedupe+normalize expected)", lines)
	}
}

func TestBuildAlterXRejectsInvalidHost(t *testing.T) {
	b := NewBuilder("example.com", "", "", "alterx")
	if _, err := b.BuildAlterXCandidates([]string{"api.example.com", "evil;id"}); err == nil {
		t.Fatal("invalid host accepted; builders must fail closed")
	}
	if _, err := b.BuildAlterXCandidates([]string{"out.example.net"}); err != nil {
		// boundary filtering is the caller's job (scope filter); builder only
		// checks syntax, so this must NOT fail
		t.Fatalf("syntactically valid host rejected: %v", err)
	}
}

func TestBuildDNSXBruteforceUsesMaterializedWordlist(t *testing.T) {
	b := NewBuilder("example.com", "", "/opt/tools/dnsx", "")
	spec, err := b.BuildDNSXBruteforce("/managed/data/work/wordlist-preset-small.txt", scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spec.Args, " ")
	if !strings.Contains(joined, "-w /managed/data/work/wordlist-preset-small.txt") {
		t.Fatalf("argv = %v", spec.Args)
	}
	if !strings.Contains(joined, "-d example.com") {
		t.Fatalf("argv = %v", spec.Args)
	}
	if _, err := b.BuildDNSXBruteforce("", scope.DefaultPolicy()); err == nil {
		t.Fatal("empty wordlist path accepted")
	}
	if _, err := b.BuildDNSXBruteforce("--flag-from-agent", scope.DefaultPolicy()); err == nil {
		t.Fatal("agent-supplied flag-as-path accepted")
	}
}

func TestBuildDNSXResolveStdin(t *testing.T) {
	b := NewBuilder("example.com", "", "/opt/tools/dnsx", "")
	spec, err := b.BuildDNSXResolve([]string{"a.example.com", "A.EXAMPLE.COM.", "b.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spec.Args, " ")
	for _, want := range []string{"-l -", "-silent", "-json", "-omit-raw", "-a -aaaa -cname -resp", "-retry 1", "-timeout 3s", "-t 10", "-rl 10", "-duc"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("argv missing %q: %v", want, spec.Args)
		}
	}
	if len(spec.Args) == 0 {
		t.Fatalf("argv = %v", spec.Args)
	}
	lines := strings.Split(strings.TrimSpace(spec.Stdin), "\n")
	if len(lines) != 2 {
		t.Fatalf("stdin = %q", spec.Stdin)
	}
	if _, err := b.BuildDNSXResolve(nil); err == nil {
		t.Fatal("empty host list accepted")
	}
}

func TestFakeRunnerRecordsAndReplays(t *testing.T) {
	fake := &FakeRunner{Fn: func(spec ExecSpec) ([]byte, []byte, error) {
		return []byte("api.example.com\n"), nil, nil
	}}
	ctx := context.Background()
	spec := ExecSpec{Binary: "subfinder", Args: []string{"-d", "example.com", "-silent", "-json"}, Timeout: 30 * time.Second}
	out, _, err := fake.Run(ctx, spec)
	if err != nil {
		t.Fatal(err)
	}
	if string(out) != "api.example.com\n" {
		t.Fatalf("out = %q", out)
	}
	if fake.CallCount() != 1 || !strings.Contains(fake.Calls[0].Describe(), "-d example.com") {
		t.Fatalf("calls = %+v", fake.Calls)
	}
}

func TestFakeRunnerErrorAndTimeoutInjection(t *testing.T) {
	fake := &FakeRunner{Fn: func(ExecSpec) ([]byte, []byte, error) {
		return nil, []byte("boom"), errors.New("exit status 1")
	}}
	if _, _, err := fake.Run(context.Background(), ExecSpec{Binary: "dnsx"}); err == nil {
		t.Fatal("expected injected error")
	}

	fake2 := &FakeRunner{Fn: func(ExecSpec) ([]byte, []byte, error) {
		time.Sleep(50 * time.Millisecond)
		return nil, nil, errors.New("context deadline exceeded")
	}}
	done := make(chan error, 1)
	start := time.Now()
	go func() {
		_, _, err := fake2.Run(context.Background(), ExecSpec{Binary: "dnsx", Timeout: 10 * time.Millisecond})
		done <- err
	}()
	if err := <-done; err == nil {
		t.Fatal("expected timeout-style error")
	}
	if time.Since(start) < 10*time.Millisecond {
		t.Fatal("returned before the fake delay")
	}
}

func TestExecRunnerRejectsMissingBinaryWithoutShell(t *testing.T) {
	r := ExecRunner{}
	_, _, err := r.Run(context.Background(), ExecSpec{
		Binary:  "/nonexistent/subenum-definitely-missing-binary",
		Args:    []string{"-d", "example.com"},
		Timeout: 2 * time.Second,
	})
	if err == nil {
		t.Fatal("expected error for missing binary")
	}
	if strings.Contains(err.Error(), "/bin/sh") || strings.Contains(err.Error(), "sh -c") {
		t.Fatalf("runner appears to use a shell: %v", err)
	}
}

func TestExecSpecHasNoShellInvocation(t *testing.T) {
	specs := []ExecSpec{}
	b := NewBuilder("example.com", "subfinder", "dnsx", "alterx")
	s1, err := b.BuildSubfinderDiscover(scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	s2, err := b.BuildDNSXResolve([]string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	s3, err := b.BuildAlterXCandidates([]string{"a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	specs = append(specs, s1, s2, s3)
	for _, spec := range specs {
		if len(spec.Args) > 0 && (spec.Args[0] == "sh" || spec.Args[0] == "bash") {
			t.Fatalf("shell wrapper found: %v", spec.Args)
		}
		if strings.Contains(spec.Binary, " ") {
			t.Fatalf("binary must be a bare path, not a command line: %q", spec.Binary)
		}
	}
}
