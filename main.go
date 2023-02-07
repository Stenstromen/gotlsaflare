package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
)

func getSHA256sum() {
	// read file content
	pemContent, err := ioutil.ReadFile("./cert.pem")
	if err != nil {
		panic(err)
	}

	block, _ := pem.Decode(pemContent)
	if block == nil {
		panic("Failed to parse pem file")
	}

	// pass cert bytes
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(err)
	}

	certPublicKey := cert.PublicKey

	fmt.Println(certPublicKey)

	fingerprint := sha256.Sum256(cert.Raw)

	var buf bytes.Buffer
	for i, f := range fingerprint {
		if i > 0 {
			fmt.Fprintf(&buf, ":")
		}
		fmt.Fprintf(&buf, "%02X", f)
	}
	fmt.Printf("Fingerprint: %s\n", buf.String())
}

func main() {
	getSHA256sum()
}
