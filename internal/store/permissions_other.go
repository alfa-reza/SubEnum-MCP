//go:build !unix

package store

import "os"

// Non-Unix platforms do not expose Unix directory permission bits as an ACL
// boundary through os.Chmod; the platform's inherited ACL remains authoritative.
func restrictPrivateDirectory(_ *os.Root, _ string) error { return nil }
