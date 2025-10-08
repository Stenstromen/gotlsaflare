package resource

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Helper function to generate a test certificate for genCloudflareReq tests
func generateTestCertForReq(t *testing.T) string {
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

	certBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "test_cert.pem")

	f, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer f.Close()

	if err := pem.Encode(f, &pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certBytes,
	}); err != nil {
		t.Fatalf("Failed to write certificate: %v", err)
	}

	return certPath
}

func TestGenCloudflareReq_DANEEE_SHA256(t *testing.T) {
	certPath := generateTestCertForReq(t)

	result := genCloudflareReq(certPath, "25", "tcp", "mail", "Created", 3, 1, 1)

	// Parse the JSON result
	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	// Verify the structure
	if jsonReq.Type != "TLSA" {
		t.Errorf("Expected Type 'TLSA', got '%s'", jsonReq.Type)
	}

	expectedName := "_25._tcp.mail"
	if jsonReq.Name != expectedName {
		t.Errorf("Expected Name '%s', got '%s'", expectedName, jsonReq.Name)
	}

	if jsonReq.Data.Usage != 3 {
		t.Errorf("Expected Usage 3, got %d", jsonReq.Data.Usage)
	}

	if jsonReq.Data.Selector != 1 {
		t.Errorf("Expected Selector 1, got %d", jsonReq.Data.Selector)
	}

	if jsonReq.Data.Matchingtype != 1 {
		t.Errorf("Expected Matchingtype 1, got %d", jsonReq.Data.Matchingtype)
	}

	if jsonReq.Data.Certificate == "" {
		t.Error("Expected non-empty Certificate")
	}

	if len(jsonReq.Data.Certificate) != 64 {
		t.Errorf("Expected Certificate hash length 64 (SHA256), got %d", len(jsonReq.Data.Certificate))
	}

	if jsonReq.Ttl != 3600 {
		t.Errorf("Expected TTL 3600, got %d", jsonReq.Ttl)
	}

	if jsonReq.Priority != 10 {
		t.Errorf("Expected Priority 10, got %d", jsonReq.Priority)
	}

	if jsonReq.Proxied != false {
		t.Errorf("Expected Proxied false, got %v", jsonReq.Proxied)
	}

	if !strings.Contains(jsonReq.Comment, "Created by GoTLSAFlare") {
		t.Errorf("Expected comment to contain 'Created by GoTLSAFlare', got '%s'", jsonReq.Comment)
	}
}

func TestGenCloudflareReq_DANEEE_SHA512(t *testing.T) {
	certPath := generateTestCertForReq(t)

	result := genCloudflareReq(certPath, "443", "tcp", "www", "Updated", 3, 1, 2)

	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if jsonReq.Data.Matchingtype != 2 {
		t.Errorf("Expected Matchingtype 2 (SHA512), got %d", jsonReq.Data.Matchingtype)
	}

	if len(jsonReq.Data.Certificate) != 128 {
		t.Errorf("Expected Certificate hash length 128 (SHA512), got %d", len(jsonReq.Data.Certificate))
	}

	if !strings.Contains(jsonReq.Comment, "Updated by GoTLSAFlare") {
		t.Errorf("Expected comment to contain 'Updated by GoTLSAFlare', got '%s'", jsonReq.Comment)
	}
}

func TestGenCloudflareReq_DANETA_SHA256(t *testing.T) {
	// Create a certificate chain (EE + CA)
	privateKey1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privateKey2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	serialNumber1, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	serialNumber2, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))

	eeCert := x509.Certificate{
		SerialNumber: serialNumber1,
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

	caCert := x509.Certificate{
		SerialNumber: serialNumber2,
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			CommonName:   "Test CA",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	eeBytes, _ := x509.CreateCertificate(rand.Reader, &eeCert, &eeCert, &privateKey1.PublicKey, privateKey1)
	caBytes, _ := x509.CreateCertificate(rand.Reader, &caCert, &caCert, &privateKey2.PublicKey, privateKey2)

	tmpDir := t.TempDir()
	certPath := filepath.Join(tmpDir, "fullchain.pem")

	f, err := os.Create(certPath)
	if err != nil {
		t.Fatalf("Failed to create cert file: %v", err)
	}
	defer f.Close()

	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: eeBytes})
	pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: caBytes})

	// Test DANE-TA (usage 2) with selector 0
	result := genCloudflareReq(certPath, "25", "tcp", "mail", "Created", 2, 0, 1)

	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if jsonReq.Data.Usage != 2 {
		t.Errorf("Expected Usage 2 (DANE-TA), got %d", jsonReq.Data.Usage)
	}

	if jsonReq.Data.Selector != 0 {
		t.Errorf("Expected Selector 0, got %d", jsonReq.Data.Selector)
	}

	if jsonReq.Data.Certificate == "" {
		t.Error("Expected non-empty Certificate (CA hash)")
	}
}

func TestGenCloudflareReq_DifferentPorts(t *testing.T) {
	certPath := generateTestCertForReq(t)

	testCases := []struct {
		port         string
		subdomain    string
		expectedName string
	}{
		{"25", "mail", "_25._tcp.mail"},
		{"465", "smtp", "_465._tcp.smtp"},
		{"587", "mail", "_587._tcp.mail"},
		{"443", "www", "_443._tcp.www"},
		{"8443", "api", "_8443._tcp.api"},
	}

	for _, tc := range testCases {
		t.Run(tc.port, func(t *testing.T) {
			result := genCloudflareReq(certPath, tc.port, "tcp", tc.subdomain, "Created", 3, 1, 1)

			var jsonReq JSONRequest
			if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			if jsonReq.Name != tc.expectedName {
				t.Errorf("Expected Name '%s', got '%s'", tc.expectedName, jsonReq.Name)
			}
		})
	}
}

func TestGenCloudflareReq_JSONFormat(t *testing.T) {
	certPath := generateTestCertForReq(t)

	result := genCloudflareReq(certPath, "25", "tcp", "mail", "Created", 3, 1, 1)

	// Verify it's valid JSON
	var jsonReq map[string]interface{}
	if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
		t.Fatalf("Result is not valid JSON: %v", err)
	}

	// Verify all required fields are present
	requiredFields := []string{"type", "name", "data", "ttl", "priority", "proxied", "comment"}
	for _, field := range requiredFields {
		if _, exists := jsonReq[field]; !exists {
			t.Errorf("Missing required field: %s", field)
		}
	}

	// Verify data subfields
	data, ok := jsonReq["data"].(map[string]interface{})
	if !ok {
		t.Fatal("'data' field is not an object")
	}

	dataFields := []string{"usage", "selector", "matching_type", "certificate"}
	for _, field := range dataFields {
		if _, exists := data[field]; !exists {
			t.Errorf("Missing required data field: %s", field)
		}
	}
}

func TestGenCloudflareReq_Selector0_FullCert(t *testing.T) {
	certPath := generateTestCertForReq(t)

	result := genCloudflareReq(certPath, "25", "tcp", "mail", "Created", 3, 0, 1)

	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
		t.Fatalf("Failed to parse JSON: %v", err)
	}

	if jsonReq.Data.Selector != 0 {
		t.Errorf("Expected Selector 0 (full cert), got %d", jsonReq.Data.Selector)
	}

	// The hash should still be 64 characters (SHA256)
	if len(jsonReq.Data.Certificate) != 64 {
		t.Errorf("Expected Certificate hash length 64, got %d", len(jsonReq.Data.Certificate))
	}
}

func TestGenCloudflareReq_CommentFormat(t *testing.T) {
	certPath := generateTestCertForReq(t)

	testCases := []struct {
		cu       string
		expected string
	}{
		{"Created", "Created by GoTLSAFlare"},
		{"Updated", "Updated by GoTLSAFlare"},
	}

	for _, tc := range testCases {
		t.Run(tc.cu, func(t *testing.T) {
			result := genCloudflareReq(certPath, "25", "tcp", "mail", tc.cu, 3, 1, 1)

			var jsonReq JSONRequest
			if err := json.Unmarshal([]byte(result), &jsonReq); err != nil {
				t.Fatalf("Failed to parse JSON: %v", err)
			}

			if !strings.HasPrefix(jsonReq.Comment, tc.expected) {
				t.Errorf("Expected comment to start with '%s', got '%s'", tc.expected, jsonReq.Comment)
			}

			// Verify timestamp format (should contain date and time)
			if !strings.Contains(jsonReq.Comment, " - ") {
				t.Error("Expected comment to contain timestamp separator ' - '")
			}
		})
	}
}
