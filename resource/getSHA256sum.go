package resource

import (
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func getHash(certfile string, selector int, matchingType int) (string, string) {
	pemContent, err := os.ReadFile(certfile)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// Get end-entity certificate (first in chain)
	block, rest := pem.Decode(pemContent)
	if block == nil {
		log.Println("Failed to parse pem file")
		os.Exit(1)
	}
	eeCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	eeHash, err := certificateHash(eeCert, selector, matchingType)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	// Get CA certificate (last in chain)
	var caCert *x509.Certificate
	for len(rest) > 0 {
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		parsed, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
		caCert = parsed
	}

	var caHash string
	if caCert != nil {
		caHash, err = certificateHash(caCert, selector, matchingType)
		if err != nil {
			log.Println(err)
			os.Exit(1)
		}
	}

	return eeHash, caHash
}

// certificateHash is the TLSA association hash.
// Selector 0 hashes the full certificate DER. Any other selector hashes the
// SubjectPublicKeyInfo, matching openssl pkey -pubin -outform DER.
// Matching type 1 is SHA2-256 and matching type 2 is SHA2-512.
func certificateHash(cert *x509.Certificate, selector int, matchingType int) (string, error) {
	if cert == nil {
		return "", fmt.Errorf("nil certificate")
	}

	var data []byte
	if selector == 0 {
		data = cert.Raw
	} else {
		var err error
		data, err = x509.MarshalPKIXPublicKey(cert.PublicKey)
		if err != nil {
			return "", err
		}
	}

	switch matchingType {
	case 1:
		sum := sha256.Sum256(data)
		return hex.EncodeToString(sum[:]), nil
	case 2:
		sum := sha512.Sum512(data)
		return hex.EncodeToString(sum[:]), nil
	default:
		return "", fmt.Errorf("unsupported matching type %d", matchingType)
	}
}

// For backward compatibility
func getSHA256sum(certfile string, selector int) (string, string) {
	return getHash(certfile, selector, 1)
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

func getPublicKeySHA512(cert *x509.Certificate) string {
	keyDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	sum := sha512.Sum512(keyDER)
	return hex.EncodeToString(sum[:])
}
