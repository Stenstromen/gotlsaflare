package resource

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
)

func getSHA256sum(certfile string) (string, string) {
	pemContent, err := os.ReadFile(certfile)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// Get end-entity certificate (first in chain)
	block, rest := pem.Decode([]byte(pemContent))
	if block == nil {
		log.Println("Failed to parse pem file")
		os.Exit(1)
	}
	eeCert, _ := x509.ParseCertificate(block.Bytes)
	eeHash := getPublicKeySHA256(eeCert)

	// Get CA certificate (last in chain)
	var caCert *x509.Certificate
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		caCert, _ = x509.ParseCertificate(block.Bytes)
	}

	var caHash string
	if caCert != nil {
		caHash = getPublicKeySHA256(caCert)
	}

	return eeHash, caHash
}

func getPublicKeySHA256(cert *x509.Certificate) string {
	keyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	sum := sha256.Sum256(keyDER)
	return hex.EncodeToString(sum[:])
}
