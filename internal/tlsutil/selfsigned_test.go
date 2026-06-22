package tlsutil

import (
	"crypto/tls"
	"os"
	"path/filepath"
	"testing"
)

func TestLoadOrCreateGeneratesUsablePair(t *testing.T) {
	dir := t.TempDir()

	cert, key, selfSigned, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if !selfSigned {
		t.Fatal("expected selfSigned=true when no cert/key provided")
	}
	if cert != filepath.Join(dir, "tls", "cert.pem") || key != filepath.Join(dir, "tls", "key.pem") {
		t.Fatalf("unexpected paths: %s %s", cert, key)
	}

	// The generated pair must load as a TLS keypair.
	if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
		t.Fatalf("generated pair does not load: %v", err)
	}

	// Key file must be 0600 (private material).
	info, err := os.Stat(key)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("key perms = %o, want 600", perm)
	}
}

func TestLoadOrCreateReusesExisting(t *testing.T) {
	dir := t.TempDir()

	cert1, _, _, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	before, err := os.ReadFile(cert1)
	if err != nil {
		t.Fatal(err)
	}

	cert2, _, _, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	after, err := os.ReadFile(cert2)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("expected the certificate to be reused, but it changed")
	}
}

func TestLoadOrCreateRegeneratesLooseSelfSignedKey(t *testing.T) {
	dir := t.TempDir()

	cert1, key1, _, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("first LoadOrCreate: %v", err)
	}
	before, err := os.ReadFile(cert1)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(key1, 0o644); err != nil {
		t.Fatalf("chmod generated key: %v", err)
	}

	cert2, key2, selfSigned, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("second LoadOrCreate: %v", err)
	}
	if !selfSigned || cert2 != cert1 || key2 != key1 {
		t.Fatalf("unexpected generated material: cert=%s key=%s selfSigned=%v", cert2, key2, selfSigned)
	}
	after, err := os.ReadFile(cert2)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("expected loose self-signed key to force certificate regeneration")
	}
	info, err := os.Stat(key2)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Fatalf("regenerated key perms = %o, want 600", perm)
	}
	if _, err := tls.LoadX509KeyPair(cert2, key2); err != nil {
		t.Fatalf("regenerated pair does not load: %v", err)
	}
}

func TestLoadOrCreateRegeneratesMismatchedSelfSignedPair(t *testing.T) {
	dirA := t.TempDir()
	certA, keyA, _, err := LoadOrCreate(dirA, "", "")
	if err != nil {
		t.Fatalf("generate pair A: %v", err)
	}
	before, err := os.ReadFile(certA)
	if err != nil {
		t.Fatal(err)
	}
	dirB := t.TempDir()
	_, keyB, _, err := LoadOrCreate(dirB, "", "")
	if err != nil {
		t.Fatalf("generate pair B: %v", err)
	}
	keyBBytes, err := os.ReadFile(keyB)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyA, keyBBytes, 0o600); err != nil {
		t.Fatalf("replace key A: %v", err)
	}

	if _, _, _, err := LoadOrCreate(dirA, "", ""); err != nil {
		t.Fatalf("LoadOrCreate regenerated mismatched pair with error: %v", err)
	}
	after, err := os.ReadFile(certA)
	if err != nil {
		t.Fatal(err)
	}
	if string(before) == string(after) {
		t.Fatal("expected mismatched self-signed pair to force certificate regeneration")
	}
	if _, err := tls.LoadX509KeyPair(certA, keyA); err != nil {
		t.Fatalf("regenerated pair does not load: %v", err)
	}
}

func TestLoadOrCreateUsesProvidedFiles(t *testing.T) {
	dir := t.TempDir()
	generatedCert, generatedKey, _, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("generate pair: %v", err)
	}

	cert, key, selfSigned, err := LoadOrCreate(t.TempDir(), generatedCert, generatedKey)
	if err != nil {
		t.Fatalf("LoadOrCreate: %v", err)
	}
	if selfSigned {
		t.Fatal("expected selfSigned=false when operator supplies cert/key")
	}
	if cert != generatedCert || key != generatedKey {
		t.Fatalf("provided paths not honored: %s %s", cert, key)
	}
}

func TestLoadOrCreateRejectsPartialProvidedFiles(t *testing.T) {
	if _, _, _, err := LoadOrCreate(t.TempDir(), "/etc/my/cert.pem", ""); err == nil {
		t.Fatal("LoadOrCreate accepted cert without key")
	}
	if _, _, _, err := LoadOrCreate(t.TempDir(), "", "/etc/my/key.pem"); err == nil {
		t.Fatal("LoadOrCreate accepted key without cert")
	}
}

func TestLoadOrCreateRejectsLooseProvidedKeyMode(t *testing.T) {
	dir := t.TempDir()
	cert, key, _, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("generate pair: %v", err)
	}
	if err := os.Chmod(key, 0o644); err != nil {
		t.Fatalf("chmod generated key: %v", err)
	}

	if _, _, _, err := LoadOrCreate(t.TempDir(), cert, key); err == nil {
		t.Fatal("LoadOrCreate accepted group/world-readable key")
	}
}

func TestLoadOrCreateRejectsProvidedKeySymlink(t *testing.T) {
	dir := t.TempDir()
	cert, key, _, err := LoadOrCreate(dir, "", "")
	if err != nil {
		t.Fatalf("generate pair: %v", err)
	}
	link := filepath.Join(t.TempDir(), "key-link.pem")
	if err := os.Symlink(key, link); err != nil {
		t.Fatal(err)
	}

	if _, _, _, err := LoadOrCreate(t.TempDir(), cert, link); err == nil {
		t.Fatal("LoadOrCreate accepted symlinked operator key")
	}
}

func TestLoadOrCreateRejectsMismatchedProvidedPair(t *testing.T) {
	dirA := t.TempDir()
	certA, _, _, err := LoadOrCreate(dirA, "", "")
	if err != nil {
		t.Fatalf("generate pair A: %v", err)
	}
	dirB := t.TempDir()
	_, keyB, _, err := LoadOrCreate(dirB, "", "")
	if err != nil {
		t.Fatalf("generate pair B: %v", err)
	}

	if _, _, _, err := LoadOrCreate(t.TempDir(), certA, keyB); err == nil {
		t.Fatal("LoadOrCreate accepted mismatched cert/key pair")
	}
}
