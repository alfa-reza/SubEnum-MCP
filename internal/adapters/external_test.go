package adapters

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/backend"
	"github.com/alfa-reza/SubEnum-MCP/internal/model"
	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

const testRoot = "corp.customer-example.net"

func TestDNSXRequiresValidPositiveAnswer(t *testing.T) {
	sc, err := scope.New(testRoot, scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		row     string
		count   int
		invalid bool
	}{
		{`{"host":"api.` + testRoot + `"}`, 0, false},
		{`{"host":"api.` + testRoot + `","a":["192.0.2.1"]}`, 1, false},
		{`{"host":"api.` + testRoot + `","a":["not-an-ip"]}`, 0, true},
		{`{"host":"api.` + testRoot + `","aaaa":["192.0.2.1"]}`, 0, true},
		{`{"host":"api.` + testRoot + `","cname":["bad name"]}`, 0, true},
	} {
		got, err := parseDNSXRecords([]byte(tc.row), sc)
		if (err != nil) != tc.invalid || len(got) != tc.count {
			t.Errorf("%s: got %v, %v", tc.row, got, err)
		}
	}
}

func testExternal(t *testing.T, fn func(ExecSpec) ([]byte, []byte, error)) (*ExternalBackends, *FakeRunner) {
	t.Helper()
	sc, err := scope.New(testRoot, scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	fake := &FakeRunner{Fn: fn}
	builder := NewBuilder(sc.Root(), "/pinned/subfinder", "/pinned/dnsx", "/pinned/alterx")
	ext, err := NewExternalBackends(sc, builder, fake)
	if err != nil {
		t.Fatal(err)
	}
	return ext, fake
}

func TestExternalDiscoverIsPassiveBoundedAndScopeFiltered(t *testing.T) {
	stdout := []byte("{\"host\":\"api." + testRoot + "\"}\n" +
		"{\"host\":\"" + testRoot + "\"}\n" +
		"fake" + testRoot + "\n" +
		"x." + testRoot + ".attacker.test\n" +
		"bad!." + testRoot + "\n")
	ext, fake := testExternal(t, func(spec ExecSpec) ([]byte, []byte, error) {
		return stdout, nil, nil
	})
	records, err := ext.Discover(context.Background(), backend.DiscoverRequest{
		RunID: "run", Root: testRoot, MaxRecords: 10, Timeout: 45 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Host != "api."+testRoot {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Status != model.StatusCandidate || records[0].InScope != true || len(records[0].Provenance) != 1 || records[0].Provenance[0].Fixture {
		t.Fatalf("external provenance/status = %+v", records[0])
	}
	if fake.CallCount() != 1 {
		t.Fatalf("runner calls = %d", fake.CallCount())
	}
	spec := fake.Calls[0]
	joined := strings.Join(spec.Args, " ")
	for _, want := range []string{"-d " + testRoot, "-oJ", "-duc", "-timeout 10", "-max-time 1", "-rl 5", "-mr 10"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("Subfinder argv missing %q: %v", want, spec.Args)
		}
	}
	for _, forbidden := range []string{"-active", "-nW", "-oI", "-ip"} {
		for _, arg := range spec.Args {
			if arg == forbidden {
				t.Fatalf("active Subfinder flag %q found in argv %v", forbidden, spec.Args)
			}
		}
	}
	if spec.Timeout != 45*time.Second {
		t.Fatalf("process timeout = %s", spec.Timeout)
	}
}

func TestDiscoverPreservesSources(t *testing.T) {
	ext, _ := testExternal(t, func(ExecSpec) ([]byte, []byte, error) {
		return []byte(`{"host":"api.` + testRoot + `","sources":["crtsh","github"]}` + "\n"), nil, nil
	})
	records, err := ext.Discover(context.Background(), backend.DiscoverRequest{RunID: "run", Root: testRoot, MaxRecords: 10})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || len(records[0].Provenance) != 3 {
		t.Fatalf("sources lost: %+v", records)
	}
}

func TestExternalGenerateFiltersSeedsAndOutput(t *testing.T) {
	ext, fake := testExternal(t, func(spec ExecSpec) ([]byte, []byte, error) {
		if spec.Binary != "/pinned/alterx" {
			return nil, nil, errors.New("wrong binary")
		}
		return []byte("new-api." + testRoot + "\n" + "api.attacker.test\n" + testRoot + "\n"), nil, nil
	})
	records, err := ext.Generate(context.Background(), backend.CandidateRequest{
		RunID: "run", Root: testRoot, Seeds: []string{"api." + testRoot, "bad.attacker.test", "api." + testRoot}, MaxOut: 7, Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Host != "new-api."+testRoot || records[0].Status != model.StatusCandidate {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Provenance[0].Backend != "alterx" || records[0].Provenance[0].Fixture {
		t.Fatalf("provenance = %+v", records[0].Provenance)
	}
	if fake.CallCount() != 1 || fake.Calls[0].Stdin != "api."+testRoot+"\n" {
		t.Fatalf("expected only normalized in-scope seed on stdin, got %+v", fake.Calls)
	}
	joined := strings.Join(fake.Calls[0].Args, " ")
	for _, want := range []string{"-limit 7", "-ms 16mb", "-duc"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("AlterX argv missing %q: %v", want, fake.Calls[0].Args)
		}
	}
}

func TestExternalBruteforceUsesBoundedServerOwnedPreset(t *testing.T) {
	managedDir := t.TempDir()
	providedWordlist := filepath.Join(managedDir, "wordlist-preset-small-test.txt")
	if err := os.WriteFile(providedWordlist, []byte("api\nwww\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	var wordlistPath string
	ext, fake := testExternal(t, func(spec ExecSpec) ([]byte, []byte, error) {
		if strings.HasPrefix(spec.Stdin, "wld-") {
			// wildcard canary: no answer observed
			return nil, nil, nil
		}
		idx := -1
		for i, arg := range spec.Args {
			if arg == "-w" && i+1 < len(spec.Args) {
				idx = i + 1
				break
			}
		}
		if idx < 0 {
			return nil, nil, errors.New("dnsx wordlist flag missing")
		}
		wordlistPath = spec.Args[idx]
		data, err := os.ReadFile(wordlistPath)
		if err != nil {
			return nil, nil, err
		}
		if string(data) != "api\nwww\n" {
			return nil, nil, errors.New("wordlist was not bounded to max_words")
		}
		return []byte("{\"host\":\"api." + testRoot + "\",\"a\":[\"192.0.2.10\"]}\n"), nil, nil
	})
	records, err := ext.Bruteforce(context.Background(), backend.BruteforceRequest{
		RunID: "run", Root: testRoot, Preset: "preset-small", MaxWords: 2,
		Words: []string{"api", "www", "admin"}, WordlistPath: providedWordlist, Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Host != "api."+testRoot || records[1].Host != "www."+testRoot {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Status != model.StatusResolved || records[1].Status != model.StatusNoAnswer {
		t.Fatalf("statuses = %s, %s", records[0].Status, records[1].Status)
	}
	if records[1].Notes != model.NoteNoAnswerNotNXDOMAIN {
		t.Fatalf("no-answer note = %q", records[1].Notes)
	}
	if fake.CallCount() != 2 {
		t.Fatalf("runner calls = %d (preset + wildcard canary)", fake.CallCount())
	}
	if strings.Contains(records[0].Notes, model.NoteWildcardSuspected) {
		t.Fatalf("clean canary must not add a wildcard note: %q", records[0].Notes)
	}
	if got := len(strings.Split(strings.TrimSpace(fake.Calls[1].Stdin), "\n")); got != 3 {
		t.Fatalf("wildcard canary probed %d labels, want 3", got)
	}
	for _, host := range strings.Split(strings.TrimSpace(fake.Calls[1].Stdin), "\n") {
		if !strings.HasPrefix(host, "wld-") || !strings.HasSuffix(host, "."+testRoot) {
			t.Fatalf("canary host %q is not a random in-scope subdomain", host)
		}
	}
	joined := strings.Join(fake.Calls[0].Args, " ")
	for _, want := range []string{"-d " + testRoot, "-w ", "-retry 1", "-timeout 3s", "-t 10", "-rl 10", "-duc"} {
		if !strings.Contains(joined, want) {
			t.Fatalf("dnsx brute argv missing %q: %v", want, fake.Calls[0].Args)
		}
	}
	if wordlistPath != providedWordlist {
		t.Fatalf("dnsx wordlist = %q, want server-managed file %q", wordlistPath, providedWordlist)
	}
	if _, err := os.Stat(wordlistPath); err != nil {
		t.Fatalf("adapter removed a caller-owned managed wordlist: %v", err)
	}
}

func TestExternalBruteforceTagsWildcardSuspectedWhenCanaryAnswers(t *testing.T) {
	managedDir := t.TempDir()
	providedWordlist := filepath.Join(managedDir, "wordlist-preset-small-canary.txt")
	if err := os.WriteFile(providedWordlist, []byte("api\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	ext, fake := testExternal(t, func(spec ExecSpec) ([]byte, []byte, error) {
		if strings.HasPrefix(spec.Stdin, "wld-") {
			first := strings.Split(strings.TrimSpace(spec.Stdin), "\n")[0]
			return []byte(`{"host":"` + first + `","a":["203.0.113.9"]}` + "\n"), nil, nil
		}
		return []byte("{\"host\":\"api." + testRoot + "\",\"a\":[\"192.0.2.10\"]}\n"), nil, nil
	})
	wildcardStatus := ""
	records, err := ext.Bruteforce(context.Background(), backend.BruteforceRequest{
		RunID: "run", Root: testRoot, Preset: "preset-small", MaxWords: 1,
		Words: []string{"api"}, WordlistPath: providedWordlist, Timeout: 30 * time.Second, WildcardStatus: &wildcardStatus,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 1 || records[0].Status != model.StatusResolved {
		t.Fatalf("records = %+v", records)
	}
	if !strings.Contains(records[0].Notes, model.NoteWildcardSuspected) {
		t.Fatalf("wildcard-suspected note missing: %q", records[0].Notes)
	}
	if wildcardStatus != "suspected" {
		t.Fatalf("wildcard status = %q", wildcardStatus)
	}
	if fake.CallCount() != 2 {
		t.Fatalf("runner calls = %d, want preset + canary", fake.CallCount())
	}
}

func TestWildcardCheckOutcomes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		answer    bool
		canaryErr bool
		unrelated bool
		want      string
	}{
		{"not checked", false, false, false, "not_checked"},
		{"no canary answer", true, false, false, "no_canary_answer"},
		{"canary failure", true, true, false, "unknown"},
		{"unrelated answer", true, false, true, "no_canary_answer"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wordlist := filepath.Join(t.TempDir(), "wordlist-preset-small-test.txt")
			if err := os.WriteFile(wordlist, []byte("api\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			ext, _ := testExternal(t, func(spec ExecSpec) ([]byte, []byte, error) {
				if spec.Stdin != "" {
					if tc.canaryErr {
						return nil, nil, errors.New("canary failed")
					}
					if tc.unrelated {
						return []byte("{\"host\":\"api." + testRoot + "\",\"a\":[\"192.0.2.10\"]}\n"), nil, nil
					}
					return nil, nil, nil
				}
				if tc.answer {
					return []byte("{\"host\":\"api." + testRoot + "\",\"a\":[\"192.0.2.10\"]}\n"), nil, nil
				}
				return nil, nil, nil
			})
			status := "unset"
			_, err := ext.Bruteforce(context.Background(), backend.BruteforceRequest{Root: testRoot, Preset: "preset-small", MaxWords: 1, Words: []string{"api"}, WordlistPath: wordlist, WildcardStatus: &status})
			if err != nil || status != tc.want {
				t.Fatalf("status=%q err=%v; want %q", status, err, tc.want)
			}
		})
	}
}

func TestExternalResolveOnlyCallsDNSForInScopeHosts(t *testing.T) {
	ext, fake := testExternal(t, func(spec ExecSpec) ([]byte, []byte, error) {
		if spec.Stdin != "www."+testRoot+"\napi."+testRoot+"\n" {
			return nil, nil, errors.New("out-of-scope/apex input reached dnsx")
		}
		return []byte("{\"host\":\"www." + testRoot + "\",\"cname\":[\"edge.example.net\"]}\n"), nil, nil
	})
	records, err := ext.Resolve(context.Background(), backend.ResolveRequest{
		RunID: "run", Root: testRoot,
		Hosts:    []string{"www." + testRoot, testRoot, "fake" + testRoot, "api." + testRoot},
		MaxHosts: 10, Timeout: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || records[0].Host != "www."+testRoot || records[1].Host != "api."+testRoot {
		t.Fatalf("records = %+v", records)
	}
	if records[0].Status != model.StatusResolved || records[1].Status != model.StatusNoAnswer {
		t.Fatalf("statuses = %s, %s", records[0].Status, records[1].Status)
	}
	if len(records[0].FixtureDNSRecords) != 0 {
		t.Fatalf("live DNS response must not be mislabeled as fixture data: %+v", records[0])
	}
	if got := records[0].ObservedDNSRecords["CNAME"]; len(got) != 1 || got[0] != "edge.example.net" {
		t.Fatalf("live DNS values lost: %v", got)
	}
	if fake.CallCount() != 1 {
		t.Fatalf("runner calls = %d", fake.CallCount())
	}
}

func TestExternalResolveRejectsMalformedDNSXOutput(t *testing.T) {
	stdout := []byte("{\"host\":\"api." + testRoot + "\",\"a\":[\"192.0.2.10\"]}\n{\"host\":\n")
	ext, fake := testExternal(t, func(ExecSpec) ([]byte, []byte, error) {
		return stdout, nil, nil
	})
	_, err := ext.Resolve(context.Background(), backend.ResolveRequest{
		RunID: "run", Root: testRoot,
		Hosts: []string{"api." + testRoot, "www." + testRoot}, MaxHosts: 10,
	})
	if err == nil {
		t.Fatalf("malformed dnsx JSONL was silently accepted and could mislabel a host no_answer; calls=%d", fake.CallCount())
	}
}

func TestParseDNSXNamesRejectsOutputOverCaptureCap(t *testing.T) {
	sc, err := scope.New(testRoot, scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	stdout := []byte(strings.Repeat(" ", MaxOutputBytes+1))
	if _, err := ParseDNSXNames(stdout, sc); err == nil || !strings.Contains(err.Error(), "cap") {
		t.Fatalf("oversized dnsx output error = %v, want capture-cap refusal", err)
	}
}

func TestExternalCapsTimeoutsAndCancellationFailClosed(t *testing.T) {
	ext, fake := testExternal(t, func(ExecSpec) ([]byte, []byte, error) { return nil, nil, nil })
	_, err := ext.Discover(context.Background(), backend.DiscoverRequest{Root: testRoot, MaxRecords: 5001})
	if err == nil || fake.CallCount() != 0 {
		t.Fatalf("oversized discover request should fail before runner; err=%v calls=%d", err, fake.CallCount())
	}
	_, err = ext.Generate(context.Background(), backend.CandidateRequest{Root: testRoot, Seeds: []string{"api." + testRoot}, MaxOut: 5001})
	if err == nil || fake.CallCount() != 0 {
		t.Fatalf("oversized candidate request should fail before runner; err=%v calls=%d", err, fake.CallCount())
	}
	_, err = ext.Bruteforce(context.Background(), backend.BruteforceRequest{Root: testRoot, Preset: "preset-small", MaxWords: 1001, Words: []string{"api"}})
	if err == nil || fake.CallCount() != 0 {
		t.Fatalf("oversized wordlist request should fail before runner; err=%v calls=%d", err, fake.CallCount())
	}
	tooManyHosts := make([]string, MaxExternalResolve+1)
	_, err = ext.Resolve(context.Background(), backend.ResolveRequest{Root: testRoot, Hosts: tooManyHosts, MaxHosts: MaxExternalResolve})
	if err == nil || fake.CallCount() != 0 {
		t.Fatalf("oversized resolve request should fail before runner; err=%v calls=%d", err, fake.CallCount())
	}
	_, err = NewBuilder(testRoot, "/pinned/subfinder", "", "").BuildSubfinderDiscoverBounded(scope.DefaultPolicy(), 1, 301*time.Second)
	if err == nil {
		t.Fatal("timeout over hard cap accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = ext.Discover(ctx, backend.DiscoverRequest{Root: testRoot, MaxRecords: 1})
	if !errors.Is(err, context.Canceled) || fake.CallCount() != 0 {
		t.Fatalf("cancelled call should not reach runner; err=%v calls=%d", err, fake.CallCount())
	}
	started := make(chan struct{})
	ext2, fake2 := testExternal(t, func(ExecSpec) ([]byte, []byte, error) { return nil, nil, nil })
	fake2.Fn = nil
	fake2.FnContext = func(ctx context.Context, _ ExecSpec) ([]byte, []byte, error) {
		close(started)
		<-ctx.Done()
		return nil, nil, ctx.Err()
	}
	ctx2, cancel2 := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		_, callErr := ext2.Discover(ctx2, backend.DiscoverRequest{Root: testRoot, MaxRecords: 1, Timeout: time.Minute})
		done <- callErr
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		cancel2()
		t.Fatal("fake backend did not start")
	}
	cancel2()
	select {
	case callErr := <-done:
		if !errors.Is(callErr, context.Canceled) || fake2.CallCount() != 1 {
			t.Fatalf("in-flight cancellation error=%v calls=%d", callErr, fake2.CallCount())
		}
	case <-time.After(time.Second):
		t.Fatal("external adapter did not return after cancellation")
	}
}

func TestExternalRootMustMatchConfiguredScope(t *testing.T) {
	ext, fake := testExternal(t, func(ExecSpec) ([]byte, []byte, error) { return nil, nil, nil })
	_, err := ext.Discover(context.Background(), backend.DiscoverRequest{Root: "other.customer-example.net", MaxRecords: 1})
	if err == nil || fake.CallCount() != 0 {
		t.Fatalf("root mismatch should fail before runner; err=%v calls=%d", err, fake.CallCount())
	}
}

func TestVerifyPinnedBinaryRejectsMismatchesAndSymlinks(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "subfinder")
	if err := os.WriteFile(path, []byte("not a pinned binary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPinnedBinary("subfinder", path); err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected digest mismatch, got %v", err)
	}
	link := filepath.Join(dir, "link")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyPinnedBinary("subfinder", link); err == nil || !strings.Contains(err.Error(), "non-symlink") {
		t.Fatalf("expected symlink rejection, got %v", err)
	}
	if _, _, err := VerifyPinnedBinary("unknown", path); err == nil {
		t.Fatal("unknown backend accepted")
	}
}

func TestExecRunnerRechecksPinBeforeExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "untrusted-tool")
	marker := filepath.Join(dir, "should-not-exist")
	script := "#!/bin/sh\nprintf executed > " + marker + "\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	_, _, err := (ExecRunner{}).Run(context.Background(), ExecSpec{
		Binary: path, PinnedBackend: "subfinder", Args: []string{}, Timeout: time.Second,
	})
	if err == nil || !strings.Contains(err.Error(), "SHA-256") {
		t.Fatalf("expected pin rejection before execution, got %v", err)
	}
	if _, statErr := os.Stat(marker); !os.IsNotExist(statErr) {
		t.Fatalf("untrusted binary ran before pin rejection, marker stat err=%v", statErr)
	}
}

func TestDurationFromSecondsHardCap(t *testing.T) {
	if d, err := DurationFromSeconds(0); err != nil || d != DefaultExternalTimeout {
		t.Fatalf("default duration=%s err=%v", d, err)
	}
	if _, err := DurationFromSeconds(-1); err == nil {
		t.Fatal("negative timeout accepted")
	}
	if _, err := DurationFromSeconds(301); err == nil {
		t.Fatal("timeout above cap accepted")
	}
}

func TestResolveSalvagesPartialOutputOnTimeout(t *testing.T) {
	stdout := []byte("{\"host\":\"www." + testRoot + "\",\"a\":[\"192.0.2.10\"],\"status_code\":\"NOERROR\"}\n{\"host\":\"api." + testRoot + "\",\"status_code\":\"NXDOMAIN\"}\n")
	ext, _ := testExternal(t, func(ExecSpec) ([]byte, []byte, error) {
		return stdout, nil, context.DeadlineExceeded
	})
	records, err := ext.Resolve(context.Background(), backend.ResolveRequest{
		RunID: "run", Root: testRoot,
		Hosts:    []string{"www." + testRoot, "api." + testRoot, "mail." + testRoot},
		MaxHosts: 10, Timeout: time.Minute,
	})
	if err != nil {
		t.Fatalf("expected partial results on timeout, got err=%v", err)
	}
	if len(records) != 3 {
		t.Fatalf("records = %+v", records)
	}
	byHost := map[string]*model.Record{}
	for _, r := range records {
		byHost[r.Host] = r
	}
	if byHost["www."+testRoot].Status != model.StatusResolved {
		t.Fatalf("www status=%s", byHost["www."+testRoot].Status)
	}
	if byHost["api."+testRoot].Status != model.StatusNoAnswer || !strings.Contains(byHost["api."+testRoot].Notes, "resolver reported NXDOMAIN") {
		t.Fatalf("api nx=%+v", byHost["api."+testRoot])
	}
	if strings.Contains(byHost["mail."+testRoot].Notes, model.NoteCallTimedOut) {
		t.Fatalf("unobserved timeout record must keep its actionable note, got %q", byHost["mail."+testRoot].Notes)
	}
	if !strings.Contains(byHost["www."+testRoot].Notes, model.NoteCallTimedOut) {
		t.Fatalf("observed record should note the call reached its limit, got %q", byHost["www."+testRoot].Notes)
	}
	if byHost["mail."+testRoot].Status != model.StatusTimeout {
		t.Fatalf("mail status=%s note=%q", byHost["mail."+testRoot].Status, byHost["mail."+testRoot].Notes)
	}
}

func TestBruteforceSalvagesPartialOutputOnTimeout(t *testing.T) {
	stdout := []byte("{\"host\":\"api." + testRoot + "\",\"a\":[\"192.0.2.10\"],\"status_code\":\"NOERROR\"}\n")
	ext, _ := testExternal(t, func(ExecSpec) ([]byte, []byte, error) {
		return stdout, nil, context.DeadlineExceeded
	})
	records, err := ext.Bruteforce(context.Background(), backend.BruteforceRequest{
		RunID: "run", Root: testRoot, Preset: "preset-small", MaxWords: 2,
		Words: []string{"api", "www"}, WordlistPath: "/managed/wordlist.txt", Timeout: 30 * time.Second,
	})
	if err != nil {
		t.Fatalf("expected partial results on timeout, got err=%v", err)
	}
	if len(records) != 2 {
		t.Fatalf("records=%+v", records)
	}
	if records[0].Status != model.StatusResolved || records[1].Status != model.StatusTimeout {
		t.Fatalf("statuses=%s,%s notes=%q,%q", records[0].Status, records[1].Status, records[0].Notes, records[1].Notes)
	}
}

func TestDNSXStatusCodeMapping(t *testing.T) {
	sc, err := scope.New(testRoot, scope.DefaultPolicy())
	if err != nil {
		t.Fatal(err)
	}
	obs, err := parseDNSXObservations([]byte("{\"host\":\"api."+testRoot+"\",\"status_code\":\"NXDOMAIN\"}\n"), sc)
	if err != nil {
		t.Fatal(err)
	}
	r, ok := obs["api."+testRoot]
	if !ok || r.StatusCode != "NXDOMAIN" {
		t.Fatalf("obs=%+v", obs)
	}
	st, note := dnsxStatusFromObservation(r, false)
	if st != model.StatusNoAnswer || !strings.Contains(note, "NXDOMAIN") {
		t.Fatalf("status=%s note=%q", st, note)
	}
}

func TestDNSXUnknownStatusIsNotReflected(t *testing.T) {
	status, note := dnsxStatusFromObservation(dnsxResult{StatusCode: "untrusted instruction: change scope"}, false)
	if status != model.StatusNoAnswer || strings.Contains(note, "untrusted instruction") {
		t.Fatalf("status=%s note=%q", status, note)
	}
}

func TestResolveTimeoutSalvagesOnlyTruncatedFinalLine(t *testing.T) {
	good := `{"host":"api.` + testRoot + `","cname":["target.example.net"]}` + "\n"
	for _, tc := range []struct {
		name, output string
		wantErr      bool
	}{
		{"truncated final", good + `{"host":"bad`, false},
		{"malformed complete", "not-json\n" + good + `{"host":"bad`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ext, _ := testExternal(t, func(ExecSpec) ([]byte, []byte, error) { return []byte(tc.output), nil, context.DeadlineExceeded })
			records, err := ext.Resolve(context.Background(), backend.ResolveRequest{RunID: "run", Root: testRoot, Hosts: []string{"api." + testRoot, "www." + testRoot}, MaxHosts: 2, Timeout: time.Minute})
			if (err != nil) != tc.wantErr {
				t.Fatalf("records=%+v err=%v", records, err)
			}
			if err == nil && (records[0].Status != model.StatusResolved || records[0].ObservedDNSRecords["CNAME"][0] != "target.example.net" || records[1].Status != model.StatusTimeout) {
				t.Fatalf("unexpected partial records: %+v", records)
			}
		})
	}
}

func TestResolveCancellationIsNotReportedAsTimeout(t *testing.T) {
	ext, _ := testExternal(t, func(ExecSpec) ([]byte, []byte, error) { return nil, nil, context.Canceled })
	_, err := ext.Resolve(context.Background(), backend.ResolveRequest{RunID: "run", Root: testRoot, Hosts: []string{"api." + testRoot}, MaxHosts: 1, Timeout: time.Minute})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation, got %v", err)
	}
}
