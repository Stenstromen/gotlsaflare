package resource

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"log"
	"os"
)

func getSHA256sum(certfile string) string {
	pemContent, err := os.ReadFile(certfile)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	block, _ := pem.Decode([]byte(pemContent))
	if block == nil {
		log.Println("Failed to parse pem file")
		os.Exit(1)
	}
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	keyDER, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	sum := sha256.Sum256([]byte(keyDER))
	sha256sum := hex.EncodeToString(sum[:])
	return sha256sum
}
