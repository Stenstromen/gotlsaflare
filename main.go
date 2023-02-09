package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
)

type JSONResponse struct {
	Type   string `json:"type"`
	Name   string `json:"name"`
	Nested Nested `json:"data"`
}

type Nested struct {
	NestValue1 string `json:"nestkey1"`
	NestValue2 string `json:"nestkey2"`
}

func getSHA256sum() string {
	pemContent, err := os.ReadFile("./cert.pem")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode([]byte(pemContent))
	if block == nil {
		panic("Failed to parse pem file")
	}
	var cert *x509.Certificate
	cert, _ = x509.ParseCertificate(block.Bytes)
	rsaPublicKey := cert.PublicKey.(*rsa.PublicKey)
	keyDER, err := x509.MarshalPKIXPublicKey(rsaPublicKey)
	if err != nil {
		panic(err)
	}
	sum := sha256.Sum256([]byte(keyDER))
	sha256sum := hex.EncodeToString(sum[:])
	return sha256sum
}

func main() {

	nested := Nested{
		NestValue1: "nest value 1",
		NestValue2: "nest value 2",
	}

	jsonResponse := JSONResponse{
		Type:   "TLSA",
		Name:   "_25._tcp.test",
		Nested: nested,
	}

	fmt.Println("3 1 1 " + getSHA256sum())

	byteArray, err := json.MarshalIndent(jsonResponse, "", "  ")

	if err != nil {
		fmt.Println(err)
	}
	fmt.Println(string(byteArray))

}
