package store

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
)

func randSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		panic(fmt.Sprintf("rand suffix: %v", err))
	}
	return hex.EncodeToString(b[:])
}

func rootRel(parts ...string) (string, error) {
	if len(parts) == 0 {
		return ".", nil
	}
	for _, p := range parts {
		if p == "" || p == "." || p == ".." || strings.Contains(p, "/") || strings.Contains(p, "\\") || strings.Contains(p, "..") {
			return "", fmt.Errorf("invalid path component %q", p)
		}
	}
	return filepath.Join(parts...), nil
}

func checkRootPath(root *os.Root, rel string) error {
	parts := strings.Split(filepath.ToSlash(rel), "/")
	cur := "."
	for _, part := range parts {
		if part == "" || part == "." {
			continue
		}
		cur = filepath.Join(cur, part)
		fi, err := root.Lstat(cur)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s is a symlink", symlinked, rel)
		}
	}
	return nil
}

func rootOpenFile(root *os.Root, rel string, flags int) (*os.File, error) {
	if err := checkRootPath(root, rel); err != nil {
		return nil, err
	}
	// O_NOFOLLOW closes the final-component symlink race on Unix. On other
	// platforms os.Root still confines path resolution to the managed root,
	// and the post-open identity check rejects a final symlink before writes.
	f, err := root.OpenFile(rel, flags|openNoFollowFlag, 0o600)
	if err != nil {
		return nil, err
	}
	got, statErr := f.Stat()
	listed, listErr := root.Lstat(rel)
	if statErr != nil || listErr != nil || listed.Mode()&os.ModeSymlink != 0 || !os.SameFile(got, listed) {
		f.Close()
		if listErr != nil {
			return nil, listErr
		}
		return nil, fmt.Errorf("%w: %s changed during open", symlinked, rel)
	}
	return f, nil
}

func rootReadDir(root *os.Root, rel string) ([]fs.DirEntry, error) {
	if err := checkRootPath(root, rel); err != nil {
		return nil, err
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return f.ReadDir(-1)
}

// rootReadFile reads a small file through the managed root.
func rootReadFile(root *os.Root, rel string) ([]byte, error) {
	if err := checkRootPath(root, rel); err != nil {
		return nil, err
	}
	f, err := root.Open(rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}
