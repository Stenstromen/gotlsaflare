package resource

import (
	"encoding/json"
	"log"
	"os"
	"time"
)

func genCloudflareReq(certfile string, port string, protocol string, subdomain string, cu string, usage int, selector int) string {
	currentTime := time.Now()

	eeHash, caHash := getSHA256sum(certfile, selector)
	certificate := eeHash
	if usage == 2 {
		certificate = caHash
	}

	data := Data{
		Usage:        usage,
		Selector:     selector,
		Matchingtype: 1,
		Certificate:  certificate,
	}

	jsonRequest := JSONRequest{
		Type:     "TLSA",
		Name:     "_" + port + "._" + protocol + "." + subdomain,
		Data:     data,
		Ttl:      3600,
		Priority: 10,
		Proxied:  false,
		Comment:  cu + " by GoTLSAFlare - " + currentTime.Format("2006-01-02 15:04:05"),
	}

	byteArray, err := json.MarshalIndent(jsonRequest, "", "  ")

	if err != nil {
		log.Println(err)
		os.Exit(1)
	}
	return string(byteArray)
}
