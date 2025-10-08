package resource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// Helper function to generate a test certificate
func generateTestCertificate(t *testing.T, isCA bool) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("Failed to generate serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Test Organization"},
			CommonName:   "test.example.com",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}

	if isCA {
		template.IsCA = true
		template.KeyUsage |= x509.KeyUsageCertSign
		template.Subject.CommonName = "Test CA"
	}

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certBytes)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, privateKey
}

// Helper function to write certificates to a PEM file
func writeCertsToPEMFile(t *testing.T, filename string, certs ...*x509.Certificate) string {
	t.Helper()

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, filename)

	f, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer f.Close()

	for _, cert := range certs {
		if err := pem.Encode(f, &pem.Block{
			Type:  "CERTIFICATE",
			Bytes: cert.Raw,
		}); err != nil {
			t.Fatalf("Failed to write certificate: %v", err)
		}
	}

	return certPath
}

func TestGetHash_SHA256_Selector1(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "test_cert.pem", cert)

	// Test with selector 1 (public key) and matching type 1 (SHA2-256)
	eeHash, caHash := getHash(certPath, 1, 1)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if len(eeHash) != 64 { // SHA256 produces 64 hex characters
		t.Errorf("Expected hash length 64, got %d", len(eeHash))
	}

	if caHash != "" {
		t.Error("Expected empty CA hash for single certificate")
	}
}

func TestGetHash_SHA256_Selector0(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "test_cert.pem", cert)

	// Test with selector 0 (full certificate) and matching type 1 (SHA2-256)
	eeHash, caHash := getHash(certPath, 0, 1)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if len(eeHash) != 64 { // SHA256 produces 64 hex characters
		t.Errorf("Expected hash length 64, got %d", len(eeHash))
	}

	if caHash != "" {
		t.Error("Expected empty CA hash for single certificate")
	}
}

func TestGetHash_SHA512_Selector1(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "test_cert.pem", cert)

	// Test with selector 1 (public key) and matching type 2 (SHA2-512)
	eeHash, caHash := getHash(certPath, 1, 2)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if len(eeHash) != 128 { // SHA512 produces 128 hex characters
		t.Errorf("Expected hash length 128, got %d", len(eeHash))
	}

	if caHash != "" {
		t.Error("Expected empty CA hash for single certificate")
	}
}

func TestGetHash_SHA512_Selector0(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "test_cert.pem", cert)

	// Test with selector 0 (full certificate) and matching type 2 (SHA2-512)
	eeHash, caHash := getHash(certPath, 0, 2)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if len(eeHash) != 128 { // SHA512 produces 128 hex characters
		t.Errorf("Expected hash length 128, got %d", len(eeHash))
	}

	if caHash != "" {
		t.Error("Expected empty CA hash for single certificate")
	}
}

func TestGetHash_WithCAChain_SHA256(t *testing.T) {
	// Generate test certificates (end-entity and CA)
	eeCert, _ := generateTestCertificate(t, false)
	caCert, _ := generateTestCertificate(t, true)

	certPath := writeCertsToPEMFile(t, "test_fullchain.pem", eeCert, caCert)

	// Test with selector 1 (public key) and matching type 1 (SHA2-256)
	eeHash, caHash := getHash(certPath, 1, 1)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if caHash == "" {
		t.Error("Expected non-empty CA hash for certificate chain")
	}

	if len(eeHash) != 64 {
		t.Errorf("Expected EE hash length 64, got %d", len(eeHash))
	}

	if len(caHash) != 64 {
		t.Errorf("Expected CA hash length 64, got %d", len(caHash))
	}

	// Hashes should be different
	if eeHash == caHash {
		t.Error("Expected different hashes for EE and CA certificates")
	}
}

func TestGetHash_WithCAChain_SHA512(t *testing.T) {
	// Generate test certificates (end-entity and CA)
	eeCert, _ := generateTestCertificate(t, false)
	caCert, _ := generateTestCertificate(t, true)

	certPath := writeCertsToPEMFile(t, "test_fullchain.pem", eeCert, caCert)

	// Test with selector 1 (public key) and matching type 2 (SHA2-512)
	eeHash, caHash := getHash(certPath, 1, 2)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if caHash == "" {
		t.Error("Expected non-empty CA hash for certificate chain")
	}

	if len(eeHash) != 128 {
		t.Errorf("Expected EE hash length 128, got %d", len(eeHash))
	}

	if len(caHash) != 128 {
		t.Errorf("Expected CA hash length 128, got %d", len(caHash))
	}

	// Hashes should be different
	if eeHash == caHash {
		t.Error("Expected different hashes for EE and CA certificates")
	}
}

func TestGetSHA256sum_BackwardCompatibility(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "test_cert.pem", cert)

	// Test backward compatibility function
	eeHash, caHash := getSHA256sum(certPath, 1)

	if eeHash == "" {
		t.Error("Expected non-empty EE hash")
	}

	if len(eeHash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(eeHash))
	}

	if caHash != "" {
		t.Error("Expected empty CA hash for single certificate")
	}

	// Verify it produces same result as getHash with matching type 1
	eeHash2, caHash2 := getHash(certPath, 1, 1)

	if eeHash != eeHash2 {
		t.Error("getSHA256sum should produce same result as getHash with matching type 1")
	}

	if caHash != caHash2 {
		t.Error("getSHA256sum should produce same CA hash as getHash with matching type 1")
	}
}

func TestGetPublicKeySHA256(t *testing.T) {
	cert, _ := generateTestCertificate(t, false)

	hash := getPublicKeySHA256(cert)

	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	if len(hash) != 64 {
		t.Errorf("Expected hash length 64, got %d", len(hash))
	}
}

func TestGetPublicKeySHA512(t *testing.T) {
	cert, _ := generateTestCertificate(t, false)

	hash := getPublicKeySHA512(cert)

	if hash == "" {
		t.Error("Expected non-empty hash")
	}

	if len(hash) != 128 {
		t.Errorf("Expected hash length 128, got %d", len(hash))
	}
}

func TestGetHash_DifferentSelectorResults(t *testing.T) {
	// Generate test certificate
	cert, _ := generateTestCertificate(t, false)
	certPath := writeCertsToPEMFile(t, "test_cert.pem", cert)

	// Get hashes with different selectors
	hash0, _ := getHash(certPath, 0, 1) // Full certificate
	hash1, _ := getHash(certPath, 1, 1) // Public key only

	// The hashes should be different
	if hash0 == hash1 {
		t.Error("Expected different hashes for different selectors")
	}

	if len(hash0) != 64 || len(hash1) != 64 {
		t.Errorf("Both hashes should be 64 characters long, got %d and %d", len(hash0), len(hash1))
	}
}

func TestGetHash_InvalidFile(t *testing.T) {
	// This test will cause the function to exit, so we skip it in normal test runs
	// In a production environment, you might want to refactor to return errors instead of os.Exit
	t.Skip("Skipping test that causes os.Exit")
}
