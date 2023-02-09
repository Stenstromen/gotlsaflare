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
	"time"
)

type JSONRequest struct {
	Type     string `json:"type"`
	Name     string `json:"name"`
	Data     Data   `json:"data"`
	Ttl      int    `json:"ttl"`
	Priority int    `json:"priority"`
	Proxied  bool   `json:"proxied"`
	Comment  string `json:"comment"`
}

type Data struct {
	Usage        int    `json:"usage"`
	Selector     int    `json:"selector"`
	Matchingtype int    `json:"matching_type"`
	Certificate  string `json:"certificate"`
}

func genCloudflareReq(port int, protocol string) string {
	currentTime := time.Now()

	Port := string(port)

	data := Data{
		Usage:        3,
		Selector:     1,
		Matchingtype: 1,
		Certificate:  getSHA256sum(),
	}

	// "_"+Port+"._"+protocol+"test"

	jsonRequest := JSONRequest{
		Type:     "TLSA",
		Name:     "_" + Port + "._" + protocol + "test",
		Data:     data,
		Ttl:      3600,
		Priority: 10,
		Proxied:  false,
		Comment:  "Created/Updated by GoTLSAFlare " + currentTime.Format("2006-01-02 15:04:05"),
	}

	byteArray, err := json.MarshalIndent(jsonRequest, "", "  ")

	if err != nil {
		fmt.Println(err)
	}
	return string(byteArray)
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

	fmt.Println(genCloudflareReq())

}
