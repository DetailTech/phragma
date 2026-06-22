package securefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidatePrivateFileAcceptsCurrentOwnerPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := ValidatePrivateFile(path, "test secret"); err != nil {
		t.Fatalf("ValidatePrivateFile() error = %v", err)
	}
}

func TestValidatePrivateFileRejectsLooseMode(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("secret"), 0o644); err != nil {
		t.Fatal(err)
	}
	err := ValidatePrivateFile(path, "test secret")
	if err == nil || !strings.Contains(err.Error(), "must not be group/world accessible") {
		t.Fatalf("ValidatePrivateFile() error = %v, want loose-mode rejection", err)
	}
}

func TestValidatePrivateFileRejectsDirectory(t *testing.T) {
	err := ValidatePrivateFile(t.TempDir(), "test secret")
	if err == nil || !strings.Contains(err.Error(), "must be a regular file") {
		t.Fatalf("ValidatePrivateFile() error = %v, want directory rejection", err)
	}
}

func TestValidatePrivateFileRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "secret-link")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	err := ValidatePrivateFile(link, "test secret")
	if err == nil || !strings.Contains(err.Error(), "must not be a symlink") {
		t.Fatalf("ValidatePrivateFile() error = %v, want symlink rejection", err)
	}
}
