// Package backend defines the typed adapter interfaces for enumeration
// backends and the honest capability reporting model.
package backend

import (
	"context"
	"time"

	"github.com/alfa-reza/SubEnum-MCP/internal/model"
)

// Kinds of backend adapters.
const (
	KindPassive    = "passive_discovery"
	KindCandidates = "candidate_generation"
	KindBruteforce = "bruteforce"
	KindResolver   = "resolver"
)

// Backend lifecycle states. External release metadata is compiled from reviewed
// pins; a binary is marked verified only when its digest matches that pin.
const (
	StateReadyFixture = "ready_fixture"
	StateDisabled     = "disabled"
	StateUnverified   = "unverified"
	StateReady        = "ready"
)

type Info struct {
	Name             string `json:"name"`
	Kind             string `json:"kind"`
	State            string `json:"state"`
	Version          string `json:"version,omitempty"`
	VersionVerified  bool   `json:"version_verified"`
	License          string `json:"license,omitempty"`
	LicenseVerified  bool   `json:"license_verified" jsonschema:"whether license contents were verified at runtime; false does not imply a license problem"`
	BinaryConfigured bool   `json:"binary_configured"`
	BinaryVerified   bool   `json:"binary_verified"`
	Notes            string `json:"notes,omitempty"`
}

// DiscoverRequest drives passive enumeration. v1.0.0 only enumerates names; no
// HTTP, ports, takeover checks or other features are permitted.
type DiscoverRequest struct {
	RunID      string
	Root       string
	MaxRecords int
	Timeout    time.Duration
}

type Discoverer interface {
	Discover(ctx context.Context, req DiscoverRequest) ([]*model.Record, error)
}

type CandidateRequest struct {
	RunID   string
	Root    string
	Seeds   []string
	MaxOut  int
	Timeout time.Duration
}

type CandidateGenerator interface {
	Generate(ctx context.Context, req CandidateRequest) ([]*model.Record, error)
}

// BruteforceRequest resolves a preset wordlist against the root. Wordlists
// come from a fixed preset registry; callers cannot pass arbitrary files.
type BruteforceRequest struct {
	RunID          string
	Root           string
	Preset         string
	MaxWords       int
	Words          []string
	WordlistPath   string
	Timeout        time.Duration
	WildcardStatus *string
}

type Bruteforcer interface {
	Bruteforce(ctx context.Context, req BruteforceRequest) ([]*model.Record, error)
}

type ResolveRequest struct {
	RunID    string
	Root     string
	Hosts    []string
	MaxHosts int
	Timeout  time.Duration
}

type Resolver interface {
	Resolve(ctx context.Context, req ResolveRequest) ([]*model.Record, error)
}
