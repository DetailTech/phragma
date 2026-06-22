// Package securefile centralizes checks for management-plane secret files.
package securefile

import (
	"fmt"
	"os"
	"syscall"
)

// ValidatePrivateFile verifies that path is a regular, private file owned by a
// trusted local principal. Root-run daemons require root-owned secret files;
// non-root dev runs accept files owned by the current user or root.
func ValidatePrivateFile(path, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", label, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s %s must not be a symlink", label, path)
	}
	if !info.Mode().IsRegular() {
		return fmt.Errorf("%s %s must be a regular file", label, path)
	}
	if info.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("%s %s must not be group/world accessible (chmod 600)", label, path)
	}
	return validateOwner(info, path, label)
}

func validateOwner(info os.FileInfo, path, label string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid := int(stat.Uid)
	euid := os.Geteuid()
	if euid == 0 {
		if uid != 0 {
			return fmt.Errorf("%s %s must be owned by root when controld runs as root", label, path)
		}
		return nil
	}
	if uid != euid && uid != 0 {
		return fmt.Errorf("%s %s must be owned by the current user or root", label, path)
	}
	return nil
}
