package adapters

import (
	"fmt"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/scope"
)

const (
	DefaultExternalTimeout = 2 * time.Minute
	MaxExternalTimeout     = 5 * time.Minute
	DefaultSubfinderRate   = 5
	DNSXRateLimit          = 10
	DNSXThreads            = 10
	DNSXRetry              = 1
	DNSXQueryTimeout       = "3s"
	AlterXOutputLimit      = "16mb"
)

// Builder constructs fixed argv values. Tool input contributes only validated
// data (the configured root, hostnames, bounded counts and managed file path).
// No tool accepts a shell command, arbitrary flag, resolver or file path.
type Builder struct {
	SubfinderBin string
	DnsxBin      string
	AlterxBin    string
	Root         string
}

func NewBuilder(root, subfinder, dnsx, alterx string) *Builder {
	return &Builder{SubfinderBin: subfinder, DnsxBin: dnsx, AlterxBin: alterx, Root: root}
}

func (b *Builder) require(bin, name string) error {
	if strings.TrimSpace(bin) == "" {
		return fmt.Errorf("external %s is not configured; set its pinned binary path only when deliberately enabling external mode", name)
	}
	return nil
}

func boundedTimeout(timeout time.Duration) (time.Duration, error) {
	if timeout <= 0 {
		return DefaultExternalTimeout, nil
	}
	if timeout > MaxExternalTimeout {
		return 0, fmt.Errorf("timeout %s exceeds the server hard cap of %s", timeout, MaxExternalTimeout)
	}
	return timeout, nil
}

func boundedLimit(v, cap int, name string) (int, error) {
	if v <= 0 || v > cap {
		return 0, fmt.Errorf("%s must be between 1 and the server hard cap of %d", name, cap)
	}
	return v, nil
}

// BuildSubfinderDiscover builds passive-only JSONL discovery. It deliberately
// omits active flags such as -active/-nW and -ip/-oI.
func (b *Builder) BuildSubfinderDiscover(policy scope.Policy) (ExecSpec, error) {
	return b.BuildSubfinderDiscoverBounded(policy, 5000, DefaultExternalTimeout)
}

func (b *Builder) BuildSubfinderDiscoverBounded(policy scope.Policy, maxResults int, timeout time.Duration) (ExecSpec, error) {
	if err := b.require(b.SubfinderBin, "subfinder"); err != nil {
		return ExecSpec{}, err
	}
	maxResults, err := boundedLimit(maxResults, 5000, "max_results")
	if err != nil {
		return ExecSpec{}, err
	}
	timeout, err = boundedTimeout(timeout)
	if err != nil {
		return ExecSpec{}, err
	}
	root, err := scope.Normalize(b.Root)
	if err != nil {
		return ExecSpec{}, err
	}
	if err := scope.ValidateHostname(root, policy); err != nil {
		return ExecSpec{}, err
	}
	minutes := int((timeout + time.Minute - 1) / time.Minute)
	if minutes < 1 {
		minutes = 1
	}
	return ExecSpec{
		Binary:        b.SubfinderBin,
		PinnedBackend: "subfinder",
		Args: []string{
			"-d", root, "-silent", "-nc", "-oJ", "-cs", "-duc",
			"-timeout", "10", "-max-time", strconv.Itoa(minutes),
			"-rl", strconv.Itoa(DefaultSubfinderRate), "-mr", strconv.Itoa(maxResults),
		},
		Timeout: timeout,
		Root:    root,
	}, nil
}

// BuildAlterXCandidates builds only the local permutation generator pipeline.
func (b *Builder) BuildAlterXCandidates(seeds []string) (ExecSpec, error) {
	return b.BuildAlterXCandidatesBounded(seeds, 5000, DefaultExternalTimeout)
}

func (b *Builder) BuildAlterXCandidatesBounded(seeds []string, maxOut int, timeout time.Duration) (ExecSpec, error) {
	if err := b.require(b.AlterxBin, "alterx"); err != nil {
		return ExecSpec{}, err
	}
	maxOut, err := boundedLimit(maxOut, 5000, "max_candidates")
	if err != nil {
		return ExecSpec{}, err
	}
	timeout, err = boundedTimeout(timeout)
	if err != nil {
		return ExecSpec{}, err
	}
	clean, err := sanitizeHostList(seeds)
	if err != nil {
		return ExecSpec{}, err
	}
	return ExecSpec{
		Binary:        b.AlterxBin,
		PinnedBackend: "alterx",
		Args:          []string{"-silent", "-duc", "-limit", strconv.Itoa(maxOut), "-ms", AlterXOutputLimit},
		Stdin:         strings.Join(clean, "\n") + "\n",
		Timeout:       timeout,
		IsolateHome:   true,
		Root:          b.Root,
	}, nil
}

// validMaterializedPath prevents paths/flags from being accepted from a tool
// request. Production callers supply this only from the server's work folder.
func validMaterializedPath(p string) error {
	if p == "" || strings.HasPrefix(p, "-") {
		return fmt.Errorf("wordlist path %q is not an internally materialized path", p)
	}
	if strings.ContainsAny(p, "\t\n\r;&|`$") || strings.Contains(p, "..") {
		return fmt.Errorf("wordlist path %q contains forbidden characters", p)
	}
	if !filepath.IsAbs(p) || !strings.HasSuffix(p, ".txt") {
		return fmt.Errorf("wordlist path must be an absolute path to a managed text file")
	}
	return nil
}

// BuildDNSXBruteforce builds the active DNS wordlist path. The file is
// materialized by the server from a registered preset and already truncated
// to the requested word cap.
func (b *Builder) BuildDNSXBruteforce(wordlistPath string, policy scope.Policy) (ExecSpec, error) {
	return b.BuildDNSXBruteforceBounded(wordlistPath, policy, 1000, DefaultExternalTimeout)
}

func (b *Builder) BuildDNSXBruteforceBounded(wordlistPath string, policy scope.Policy, maxWords int, timeout time.Duration) (ExecSpec, error) {
	if err := b.require(b.DnsxBin, "dnsx"); err != nil {
		return ExecSpec{}, err
	}
	if _, err := boundedLimit(maxWords, 1000, "max_words"); err != nil {
		return ExecSpec{}, err
	}
	if err := validMaterializedPath(wordlistPath); err != nil {
		return ExecSpec{}, err
	}
	timeout, err := boundedTimeout(timeout)
	if err != nil {
		return ExecSpec{}, err
	}
	root, err := scope.Normalize(b.Root)
	if err != nil {
		return ExecSpec{}, err
	}
	if err := scope.ValidateHostname(root, policy); err != nil {
		return ExecSpec{}, err
	}
	return ExecSpec{
		Binary:        b.DnsxBin,
		PinnedBackend: "dnsx",
		Args: []string{
			"-d", root, "-w", wordlistPath, "-silent", "-json", "-omit-raw",
			"-a", "-aaaa", "-cname", "-resp", "-retry", strconv.Itoa(DNSXRetry),
			"-timeout", DNSXQueryTimeout, "-t", strconv.Itoa(DNSXThreads),
			"-rl", strconv.Itoa(DNSXRateLimit), "-duc",
		},
		Timeout: timeout,
		Root:    root,
	}, nil
}

// BuildDNSXResolve builds rate-limited DNS resolution; hostnames are stdin
// data and never command-line flags.
func (b *Builder) BuildDNSXResolve(hosts []string) (ExecSpec, error) {
	return b.BuildDNSXResolveBounded(hosts, 2000, DefaultExternalTimeout)
}

func (b *Builder) BuildDNSXResolveBounded(hosts []string, maxHosts int, timeout time.Duration) (ExecSpec, error) {
	if err := b.require(b.DnsxBin, "dnsx"); err != nil {
		return ExecSpec{}, err
	}
	if _, err := boundedLimit(maxHosts, 2000, "max_hosts"); err != nil {
		return ExecSpec{}, err
	}
	timeout, err := boundedTimeout(timeout)
	if err != nil {
		return ExecSpec{}, err
	}
	clean, err := sanitizeHostList(hosts)
	if err != nil {
		return ExecSpec{}, err
	}
	if len(clean) > maxHosts {
		return ExecSpec{}, fmt.Errorf("%d hosts exceed max_hosts limit %d", len(clean), maxHosts)
	}
	return ExecSpec{
		Binary:        b.DnsxBin,
		PinnedBackend: "dnsx",
		Args: []string{
			"-l", "-", "-silent", "-json", "-omit-raw", "-a", "-aaaa", "-cname", "-resp",
			"-retry", strconv.Itoa(DNSXRetry), "-timeout", DNSXQueryTimeout,
			"-t", strconv.Itoa(DNSXThreads), "-rl", strconv.Itoa(DNSXRateLimit), "-duc",
		},
		Stdin:   strings.Join(clean, "\n") + "\n",
		Timeout: timeout,
		Root:    b.Root,
	}, nil
}

func sanitizeHostList(hosts []string) ([]string, error) {
	out := make([]string, 0, len(hosts))
	seen := map[string]bool{}
	for _, h := range hosts {
		norm, err := scope.Normalize(h)
		if err != nil {
			return nil, err
		}
		if err := scope.ValidateHostname(norm, scope.DefaultPolicy()); err != nil {
			return nil, err
		}
		if seen[norm] {
			continue
		}
		seen[norm] = true
		out = append(out, norm)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("no valid hostnames supplied; provide in-scope subdomains of the configured root")
	}
	return out, nil
}
