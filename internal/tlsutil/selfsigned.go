// Package tlsutil provides the management plane's TLS material. For v1
// the WebUI/REST gateway is served over HTTPS with a self-signed
// certificate that is generated on first run and reused thereafter.
//
// This is a standard TLS *server* setup using the Go standard library —
// it is explicitly NOT TLS interception, a MITM CA, or any crypto
// engine (those remain a locked, human-supervised effort; see
// docs/build-plan.md §9). Operators who want a real certificate supply
// their own via LoadOrCreate's certFile/keyFile.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// LoadOrCreate returns the certificate and key file paths to serve TLS
// from. If certFile and keyFile are both set, they are used as-is
// (operator-provided). Otherwise a self-signed certificate is generated
// under dir/tls/ on first call and reused on subsequent runs.
//
// It returns the resolved cert and key paths and whether the material
// was self-signed (so the caller can warn appropriately).
func LoadOrCreate(dir, certFile, keyFile string) (cert, key string, selfSigned bool, err error) {
	if certFile != "" || keyFile != "" {
		if certFile == "" || keyFile == "" {
			return "", "", false, fmt.Errorf("operator TLS material requires both cert and key paths")
		}
		if err := validateOperatorMaterial(certFile, keyFile); err != nil {
			return "", "", false, err
		}
		return certFile, keyFile, false, nil
	}

	tlsDir := filepath.Join(dir, "tls")
	cert = filepath.Join(tlsDir, "cert.pem")
	key = filepath.Join(tlsDir, "key.pem")

	// Reuse existing self-signed material if both files are present and
	// the certificate has not expired.
	if reusable(cert, key) {
		return cert, key, true, nil
	}

	if err := os.MkdirAll(tlsDir, 0o755); err != nil {
		return "", "", false, fmt.Errorf("create tls dir: %w", err)
	}
	if err := generate(cert, key); err != nil {
		return "", "", false, err
	}
	return cert, key, true, nil
}

func validateOperatorMaterial(certFile, keyFile string) error {
	if err := validateCertificateFile(certFile); err != nil {
		return err
	}
	if err := validatePrivateKeyFile(keyFile); err != nil {
		return err
	}
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		return fmt.Errorf("load operator TLS keypair: %w", err)
	}
	return nil
}

func validateCertificateFile(certFile string) error {
	certInfo, err := os.Lstat(certFile)
	if err != nil {
		return fmt.Errorf("stat TLS certificate %s: %w", certFile, err)
	}
	if certInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("TLS certificate %s must not be a symlink", certFile)
	}
	if !certInfo.Mode().IsRegular() {
		return fmt.Errorf("TLS certificate %s must be a regular file", certFile)
	}
	return nil
}

func validatePrivateKeyFile(keyFile string) error {
	keyInfo, err := os.Lstat(keyFile)
	if err != nil {
		return fmt.Errorf("stat TLS private key %s: %w", keyFile, err)
	}
	if keyInfo.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("TLS private key %s must not be a symlink", keyFile)
	}
	if !keyInfo.Mode().IsRegular() {
		return fmt.Errorf("TLS private key %s must be a regular file", keyFile)
	}
	if keyInfo.Mode().Perm()&0o077 != 0 {
		return fmt.Errorf("TLS private key %s must not be group/world accessible (chmod 600)", keyFile)
	}
	if err := secureFileOwner(keyInfo, keyFile); err != nil {
		return err
	}
	return nil
}

func secureFileOwner(info os.FileInfo, path string) error {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return nil
	}
	uid := int(stat.Uid)
	euid := os.Geteuid()
	if euid == 0 {
		if uid != 0 {
			return fmt.Errorf("%s must be owned by root when controld runs as root", path)
		}
		return nil
	}
	if uid != euid && uid != 0 {
		return fmt.Errorf("%s must be owned by the current user or root", path)
	}
	return nil
}

// reusable reports whether an existing cert/key pair can be reused: both
// files parse and the certificate is still valid for at least a day.
func reusable(certPath, keyPath string) bool {
	if err := validateCertificateFile(certPath); err != nil {
		return false
	}
	if err := validatePrivateKeyFile(keyPath); err != nil {
		return false
	}
	pair, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil || len(pair.Certificate) == 0 {
		return false
	}
	c, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return false
	}
	return time.Now().Before(c.NotAfter.Add(-24 * time.Hour))
}

// generate writes a fresh self-signed ECDSA P-256 certificate and key.
func generate(certPath, keyPath string) error {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("serial: %w", err)
	}

	host, _ := os.Hostname()
	now := time.Now()
	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "OpenNGFW management UI", Organization: []string{"OpenNGFW"}},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.AddDate(2, 0, 0), // 2 years
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.IPv4(127, 0, 0, 1), net.IPv6loopback},
	}
	if host != "" && host != "localhost" {
		tmpl.DNSNames = append(tmpl.DNSNames, host)
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	if err := writePEM(certPath, "CERTIFICATE", der, 0o644); err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}
	// Private key is sensitive: 0600.
	return writePEM(keyPath, "EC PRIVATE KEY", keyDER, 0o600)
}

func writePEM(path, blockType string, der []byte, mode os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temporary %s: %w", path, err)
	}
	tmpPath := tmp.Name()
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.Remove(tmpPath)
		}
	}()
	if err := tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod temporary %s: %w", path, err)
	}
	if err := pem.Encode(tmp, &pem.Block{Type: blockType, Bytes: der}); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("encode %s: %w", path, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temporary %s: %w", path, err)
	}
	if err := os.Rename(tmpPath, path); err != nil {
		return fmt.Errorf("install %s: %w", path, err)
	}
	cleanup = false
	return nil
}
