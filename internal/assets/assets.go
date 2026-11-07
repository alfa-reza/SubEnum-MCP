// Package assets embeds offline fixture data shipped with the server.
package assets

import (
	_ "embed"
)

// PresetSmall is the only bruteforce wordlist preset shipped in v1.
//
//go:embed wordlists/preset-small.txt
var PresetSmall string
