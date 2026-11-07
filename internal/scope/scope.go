// Package scope implements DNS label handling and subdomain scope boundary
// checks for the configured enumeration root.
package scope

import (
	"fmt"
	"strings"
	"unicode"

	"golang.org/x/net/publicsuffix"
)

const (
	MaxHostnameLen = 253
	MaxLabelLen    = 63
	MinRootLabels  = 2
)

// Drop reasons reported for hosts that are rejected at ingress.
const (
	ReasonOutOfScope = "out_of_scope"
	ReasonApex       = "apex_excluded_root_is_out_of_scope"
	ReasonNonASCII   = "non_ascii_rejected_idna_policy"
)

// Policy is reserved for future validation options. v1.0.0 accepts only ordinary
// ASCII DNS labels; it rejects Unicode and xn-- A-labels because it does not
// perform full IDNA/Punycode validation.
type Policy struct{}

func DefaultPolicy() Policy { return Policy{} }

// Normalize lowercases and trims surrounding spaces, then strips exactly one
// trailing dot ("foo.example.com." -> "foo.example.com").
func Normalize(in string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(in))
	h = strings.TrimSuffix(h, ".")
	if h == "" {
		return "", fmt.Errorf("empty hostname after normalization; provide a DNS name such as host.%s", "example.com")
	}
	return h, nil
}

// ValidateHostname checks syntactic hostname validity under the policy.
func ValidateHostname(h string, _ Policy) error {
	if h == "" {
		return fmt.Errorf("hostname is empty")
	}
	if len(h) > MaxHostnameLen {
		return fmt.Errorf("hostname exceeds %d bytes (%d); split or shorten the input", MaxHostnameLen, len(h))
	}
	for _, r := range h {
		if r > unicode.MaxASCII {
			return fmt.Errorf("hostname contains non-ASCII character %q; v1.0.0 accepts ASCII DNS names only", string(r))
		}
	}
	labels := strings.Split(h, ".")
	for i, label := range labels {
		if err := validateLabel(label, i == 0); err != nil {
			return err
		}
	}
	return nil
}

func validateLabel(label string, leading bool) error {
	if label == "" {
		return fmt.Errorf("empty DNS label (consecutive or leading dots are not valid)")
	}
	if strings.HasPrefix(label, "xn--") {
		return fmt.Errorf("IDNA A-label %q rejected because v1.0.0 does not validate Punycode", label)
	}
	if len(label) > MaxLabelLen {
		return fmt.Errorf("DNS label %q exceeds %d bytes", label, MaxLabelLen)
	}
	rest := label
	underscoreOK := false
	if leading && strings.HasPrefix(label, "_") {
		rest = label[1:]
		underscoreOK = true
	}
	if rest == "" {
		return fmt.Errorf("DNS label %q is not valid", label)
	}
	for i := 0; i < len(rest); i++ {
		c := rest[i]
		switch {
		case c >= 'a' && c <= 'z' || c >= '0' && c <= '9':
		case c == '-':
			if i == 0 && !underscoreOK {
				return fmt.Errorf("DNS label %q must not start with a hyphen", label)
			}
			if i == len(rest)-1 {
				return fmt.Errorf("DNS label %q must not end with a hyphen", label)
			}
		case c == '_' && underscoreOK:
		default:
			return fmt.Errorf("DNS label %q contains invalid character %q; use letters, digits and hyphens only", label, string(c))
		}
	}
	return nil
}

// Scope is the configured enumeration root. Only subdomains of the root are
// in scope; the apex itself is never a subdomain.
type Scope struct {
	root   string
	policy Policy
}

func New(root string, p Policy) (*Scope, error) {
	h, err := Normalize(root)
	if err != nil {
		return nil, err
	}
	if err := validateRoot(h); err != nil {
		return nil, err
	}
	if err := ValidateHostname(h, p); err != nil {
		return nil, err
	}
	if err := validateRegistrableRoot(h); err != nil {
		return nil, err
	}
	return &Scope{root: h, policy: p}, nil
}

func validateRoot(h string) error {
	labels := strings.Split(h, ".")
	if len(labels) < MinRootLabels {
		return fmt.Errorf("scope root %q must contain at least %d DNS labels", h, MinRootLabels)
	}
	for _, label := range labels {
		if strings.HasPrefix(label, "_") {
			return fmt.Errorf("scope root label %q must not start with an underscore", label)
		}
	}
	if strings.ContainsAny(h, "*?!") {
		return fmt.Errorf("scope root %q must be a literal DNS name, not a pattern", h)
	}
	return nil
}

func validateRegistrableRoot(h string) error {
	publicSuffix, _ := publicsuffix.PublicSuffix(h)
	if publicSuffix == h {
		return fmt.Errorf("scope root %q must be registrable and not a public suffix", h)
	}
	return nil
}

func FromEnv(getenv func(string) string) (*Scope, error) {
	root := strings.TrimSpace(getenv("SUBENUM_SCOPE_ROOT"))
	if root == "" {
		root = "example.com"
	}
	return New(root, DefaultPolicy())
}

func (s *Scope) Root() string { return s.root }

// Classification is the result of checking a raw hostname against the scope.
type Classification struct {
	Normalized string
	InScope    bool
	Reason     string
}

// Classify normalizes and validates host, then applies the suffix boundary
// rule: host is in scope only if it ends with "."+root for a strictly deeper
// label. The apex itself is reported with an explicit reason and is never
// in scope.
func (s *Scope) Classify(host string) Classification {
	h, err := Normalize(host)
	if err != nil {
		return Classification{Normalized: h, Reason: ReasonMalformed(err)}
	}
	if containsNonASCII(h) {
		return Classification{Normalized: h, Reason: ReasonNonASCII}
	}
	if err := ValidateHostname(h, s.policy); err != nil {
		return Classification{Normalized: h, Reason: ReasonMalformed(err)}
	}
	if h == s.root {
		return Classification{Normalized: h, Reason: ReasonApex}
	}
	if strings.HasSuffix(h, "."+s.root) {
		return Classification{Normalized: h, InScope: true}
	}
	return Classification{Normalized: h, Reason: ReasonOutOfScope}
}

func containsNonASCII(h string) bool {
	for i := 0; i < len(h); i++ {
		if h[i] >= 0x80 {
			return true
		}
	}
	return false
}

func ReasonMalformed(err error) string {
	return fmt.Sprintf("malformed_hostname: %v", err)
}

// IsReservedPlaceholder reports whether domain is a reserved documentation,
// testing or local name (RFC 2606 style) or a bare single label. External
// (non-fixture) mode always refuses to operate on placeholders, including
// the default root example.com.
func IsReservedPlaceholder(domain string) bool {
	d := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	if d == "" {
		return false
	}
	for _, reserved := range []string{"example.com", "example.net", "example.org"} {
		if d == reserved || strings.HasSuffix(d, "."+reserved) {
			return true
		}
	}
	labels := strings.Split(d, ".")
	if len(labels) == 0 {
		return false
	}
	if len(labels) == 1 {
		// Bare labels are not routable public zones; refuse them for external use.
		return true
	}
	tld := labels[len(labels)-1]
	switch tld {
	case "test", "example", "invalid", "localhost":
		return true
	}
	return false
}

// SubdomainOf returns the labels of host above the scope root, or false when
// host is not an in-scope subdomain. host must already be normalized.
func (s *Scope) SubdomainOf(host string) ([]string, bool) {
	suffix := "." + s.root
	if !strings.HasSuffix(host, suffix) {
		return nil, false
	}
	prefix := strings.TrimSuffix(host, suffix)
	if prefix == "" {
		return nil, false
	}
	return strings.Split(prefix, "."), true
}
