//go:build unix

package store

import "os"

func restrictPrivateDirectory(root *os.Root, rel string) error {
	return root.Chmod(rel, 0o700)
}
