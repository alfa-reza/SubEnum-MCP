package adapters

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

// PinnedTool describes a release that was verified from an official
// ProjectDiscovery release archive. BinarySHA256 is the digest of the
// extracted executable; ArchiveSHA256 is the official release-asset digest.
type PinnedTool struct {
	Name          string `json:"name"`
	Version       string `json:"version"`
	License       string `json:"license"`
	Platform      string `json:"platform"`
	ArchiveSHA256 string `json:"archive_sha256"`
	BinarySHA256  string `json:"binary_sha256"`
	ReleaseURL    string `json:"release_url"`
}

var pinnedTools = map[string]PinnedTool{
	"subfinder": {
		Name:          "subfinder",
		Version:       "v2.17.0",
		License:       "MIT",
		Platform:      "linux/amd64",
		ArchiveSHA256: "a39c3e5c7a26ef3c430915c4d6cbf7716a00f26769a75e9405aba796142eba37",
		BinarySHA256:  "bf4ad8590702b0bb92be9b3be185f96a230b047c9b97f2831cf8914344f0b15a",
		ReleaseURL:    "https://github.com/projectdiscovery/subfinder/releases/tag/v2.17.0",
	},
	"dnsx": {
		Name:          "dnsx",
		Version:       "v1.3.1",
		License:       "MIT",
		Platform:      "linux/amd64",
		ArchiveSHA256: "438b964653056dd51dcfe614b1a16f8bced3cc48a1d27bc07cc6fdf2ef2a9533",
		BinarySHA256:  "5fca43ddfe95922d8d88a859c1fcc59fee327bf39ae574db66d391c6675b8ba3",
		ReleaseURL:    "https://github.com/projectdiscovery/dnsx/releases/tag/v1.3.1",
	},
	"alterx": {
		Name:          "alterx",
		Version:       "v0.1.0",
		License:       "MIT",
		Platform:      "linux/amd64",
		ArchiveSHA256: "ffae5b25138cb27b58900b9b5849e02d0390385fce404252d32e469f2a0e97ac",
		BinarySHA256:  "d54445cfc4a39bbcf76ca8557be17dbf72317c990543c26d26cb8157906f34f8",
		ReleaseURL:    "https://github.com/projectdiscovery/alterx/releases/tag/v0.1.0",
	},
}

// PinnedTools returns a copy of the reviewed version/license metadata.
func PinnedTools() []PinnedTool {
	return []PinnedTool{pinnedTools["subfinder"], pinnedTools["dnsx"], pinnedTools["alterx"]}
}

// VerifyPinnedBinary checks the configured executable without launching it or
// performing any network operation. External binary execution is restricted
// to the reviewed Linux amd64 release payloads.
func VerifyPinnedBinary(name, path string) (PinnedTool, string, error) {
	pin, ok := pinnedTools[name]
	if !ok {
		return PinnedTool{}, "", fmt.Errorf("no reviewed release pin for backend %q", name)
	}
	if runtime.GOOS+"/"+runtime.GOARCH != pin.Platform {
		return PinnedTool{}, "", fmt.Errorf("%s external binary pin is only available for %s; current platform is %s/%s", name, pin.Platform, runtime.GOOS, runtime.GOARCH)
	}
	if !filepath.IsAbs(path) {
		return PinnedTool{}, "", fmt.Errorf("%s binary path must be absolute", name)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return PinnedTool{}, "", fmt.Errorf("%s binary cannot be inspected: %w", name, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
		return PinnedTool{}, "", fmt.Errorf("%s binary path must be a regular non-symlink file", name)
	}
	if info.Mode().Perm()&0111 == 0 {
		return PinnedTool{}, "", fmt.Errorf("%s binary is not executable", name)
	}
	f, err := os.Open(path)
	if err != nil {
		return PinnedTool{}, "", fmt.Errorf("%s binary cannot be opened: %w", name, err)
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return PinnedTool{}, "", fmt.Errorf("%s binary checksum failed: %w", name, err)
	}
	actual := hex.EncodeToString(h.Sum(nil))
	if actual != pin.BinarySHA256 {
		return PinnedTool{}, actual, fmt.Errorf("%s binary SHA-256 %s does not match pinned %s release payload %s", name, actual, pin.Version, pin.BinarySHA256)
	}
	return pin, actual, nil
}
