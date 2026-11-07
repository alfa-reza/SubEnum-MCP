package scope

import (
	"strings"
	"testing"
)

func TestNormalize(t *testing.T) {
	cases := []struct {
		in      string
		want    string
		wantErr bool
	}{
		{"api.example.com", "api.example.com", false},
		{"  API.Example.COM ", "api.example.com", false},
		{"api.example.com.", "api.example.com", false},
		{"API.EXAMPLE.COM.", "api.example.com", false},
		{"", "", true},
		{"   ", "", true},
		{".", "", true},
	}
	for _, c := range cases {
		got, err := Normalize(c.in)
		if c.wantErr {
			if err == nil {
				t.Errorf("Normalize(%q) want error, got %q", c.in, got)
			}
			continue
		}
		if err != nil {
			t.Errorf("Normalize(%q) unexpected error: %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("Normalize(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func newScope(t *testing.T, root string) *Scope {
	t.Helper()
	s, err := New(root, DefaultPolicy())
	if err != nil {
		t.Fatalf("New(%q): %v", root, err)
	}
	return s
}

func TestClassify_BoundaryAndApex(t *testing.T) {
	s := newScope(t, "example.com")
	cases := []struct {
		in      string
		inScope bool
		reason  string
	}{
		{"api.example.com", true, ""},
		{"a.b.c.EXAMPLE.com", true, ""},
		{"x-y.example.com.", true, ""},
		{"example.com", false, ReasonApex},
		{"EXAMPLE.COM.", false, ReasonApex},
		{"badexample.com", false, ReasonOutOfScope},
		{"example.com.evil.test", false, ReasonOutOfScope},
		{"example.com.attacker.example", false, ReasonOutOfScope},
		{"foo.badexample.com", false, ReasonOutOfScope},
		{"sub.example-community.org", false, ReasonOutOfScope},
		{"", false, "malformed_hostname"},
		{"..example.com", false, "malformed_hostname"},
		{".example.com", false, "malformed_hostname"},
		{"foo..example.com", false, "malformed_hostname"},
		{"foo.example.com..", false, "malformed_hostname"},
		{"-foo.example.com", false, "malformed_hostname"},
		{"foo-.example.com", false, "malformed_hostname"},
		{"*.example.com", false, "malformed_hostname"},
		{"foo_bar.example.com", false, "malformed_hostname"},
		{"_dmarc.example.com", true, ""},
		{"_acme-challenge.api.example.com", true, ""},
		{"foo@example.com", false, "malformed_hostname"},
		{"foo.example.com:443", false, "malformed_hostname"},
		{"203.0.113.5", false, ReasonOutOfScope},
	}
	for _, c := range cases {
		got := s.Classify(c.in)
		if got.InScope != c.inScope {
			t.Errorf("Classify(%q) InScope=%v (reason %q), want %v", c.in, got.InScope, got.Reason, c.inScope)
		}
		if !c.inScope && c.reason != "" && !contains(got.Reason, c.reason) {
			t.Errorf("Classify(%q) reason %q, want containing %q", c.in, got.Reason, c.reason)
		}
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestClassify_IDNAPolicy(t *testing.T) {
	s := newScope(t, "example.com")
	got := s.Classify("büscher.example.com")
	if got.InScope {
		t.Fatal("non-ASCII hostname must be rejected")
	}
	if got.Reason != ReasonNonASCII {
		t.Fatalf("reason = %q, want %q", got.Reason, ReasonNonASCII)
	}

	// A-label syntax alone does not prove valid Punycode; v1.0.0 rejects it.
	got = s.Classify("xn--bcher-kva.example.com")
	if got.InScope || !strings.Contains(got.Reason, "IDNA A-label") {
		t.Fatalf("punycode hostname should be rejected, got %+v", got)
	}
	got = s.Classify("xn--not-valid-punycode.example.com")
	if got.InScope || !strings.Contains(got.Reason, "IDNA A-label") {
		t.Fatalf("malformed punycode hostname should be rejected, got %+v", got)
	}

	// Deep unicode label past the leftmost position also rejected.
	if got := s.Classify("api.büscher.example.com"); got.InScope || got.Reason != ReasonNonASCII {
		t.Fatalf("deep unicode label mishandled: %+v", got)
	}
}

func TestNew_RootValidation(t *testing.T) {
	for _, bad := range []string{"", "localhost", "singlelabel", "*.example.com", "_dmarc.example.com", "a..com", "-x.example.com", "x-.example.com", "ünicode.example.com"} {
		if _, err := New(bad, DefaultPolicy()); err == nil {
			t.Errorf("New(%q) expected error", bad)
		}
	}
	for _, good := range []string{"example.com", "example.org", "a-b.example.com", "OPERATOR.internal.example.com.", "example.com."} {
		s, err := New(good, DefaultPolicy())
		if err != nil {
			t.Errorf("New(%q) unexpected error: %v", good, err)
			continue
		}
		wantRoot := "example.com"
		switch good {
		case "example.org":
			wantRoot = "example.org"
		case "a-b.example.com":
			wantRoot = "a-b.example.com"
		case "OPERATOR.internal.example.com.":
			wantRoot = "operator.internal.example.com"
		}
		if s.Root() != wantRoot {
			t.Errorf("New(%q) root = %q, want %q", good, s.Root(), wantRoot)
		}
	}
}

func TestNewRejectsPublicSuffixAsScopeRoot(t *testing.T) {
	for _, root := range []string{"com", "co.uk"} {
		if _, err := New(root, DefaultPolicy()); err == nil {
			t.Errorf("New(%q) accepted a public suffix as an enumeration root", root)
		}
	}
	for _, root := range []string{"example.com", "customer.co.uk"} {
		if _, err := New(root, DefaultPolicy()); err != nil {
			t.Errorf("New(%q) unexpectedly rejected registrable root: %v", root, err)
		}
	}
}

func TestClassify_LongNames(t *testing.T) {
	s := newScope(t, "example.com")
	longLabel := strings.Repeat("a", 64) + ".example.com"
	got := s.Classify(longLabel)
	if got.InScope || !strings.Contains(got.Reason, "malformed_hostname") {
		t.Fatalf("over-long label = %+v, want malformed rejection", got)
	}
	longHost := strings.Repeat("a.", 130) + "example.com"
	got = s.Classify(longHost)
	if got.InScope {
		t.Fatalf("over-long hostname accepted: %d bytes", len(longHost))
	}
}

func TestFromEnv(t *testing.T) {
	got, err := FromEnv(func(string) string { return "" })
	if err != nil {
		t.Fatal(err)
	}
	if got.Root() != "example.com" {
		t.Fatalf("default root = %q, want example.com", got.Root())
	}
	got, err = FromEnv(func(k string) string {
		if k == "SUBENUM_SCOPE_ROOT" {
			return " corp.internal.example.COM. "
		}
		return ""
	})
	if err != nil {
		t.Fatal(err)
	}
	if got.Root() != "corp.internal.example.com" {
		t.Fatalf("env root = %q", got.Root())
	}
}

func TestIsReservedPlaceholder(t *testing.T) {
	placeholders := []string{
		"example.com", "EXAMPLE.com.", "sub.example.com", "deep.sub.example.org", "example.net", "example.org", "foo.test",
		"foo.example", "x.invalid", "localhost", "sub.localhost", "myhost",
		"corp.example.net.evil.test", "example.com.evil.test", "localhost.corp.example",
	}
	for _, p := range placeholders {
		if !IsReservedPlaceholder(p) {
			t.Errorf("IsReservedPlaceholder(%q) = false, want true", p)
		}
	}
	notPlaceholders := []string{"customer.example-brand.com", "examplebrand.com", "test.example-corp.com", "evil.example.commercial"}
	for _, p := range notPlaceholders {
		if IsReservedPlaceholder(p) {
			t.Errorf("IsReservedPlaceholder(%q) = true, want false", p)
		}
	}
}

func TestSubdomainOf(t *testing.T) {
	s := newScope(t, "example.com")
	labels, ok := s.SubdomainOf("a.b.example.com")
	if !ok || len(labels) != 2 || labels[0] != "a" || labels[1] != "b" {
		t.Fatalf("SubdomainOf deep host = %v, %v", labels, ok)
	}
	if _, ok := s.SubdomainOf("example.com"); ok {
		t.Fatal("apex must not be a subdomain")
	}
	if _, ok := s.SubdomainOf("example.org"); ok {
		t.Fatal("other suffix must not be a subdomain")
	}
}
