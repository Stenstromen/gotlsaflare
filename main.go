package main

import (
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
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

type Res struct {
	Result []struct {
		ID                  string      `json:"id"`
		Name                string      `json:"name"`
		Status              string      `json:"status"`
		Paused              bool        `json:"paused"`
		Type                string      `json:"type"`
		DevelopmentMode     int         `json:"development_mode"`
		NameServers         []string    `json:"name_servers"`
		OriginalNameServers []string    `json:"original_name_servers"`
		OriginalRegistrar   interface{} `json:"original_registrar"`
		OriginalDnshost     interface{} `json:"original_dnshost"`
		ModifiedOn          time.Time   `json:"modified_on"`
		CreatedOn           time.Time   `json:"created_on"`
		ActivatedOn         time.Time   `json:"activated_on"`
		Meta                struct {
			Step                    int  `json:"step"`
			CustomCertificateQuota  int  `json:"custom_certificate_quota"`
			PageRuleQuota           int  `json:"page_rule_quota"`
			PhishingDetected        bool `json:"phishing_detected"`
			MultipleRailgunsAllowed bool `json:"multiple_railguns_allowed"`
		} `json:"meta"`
		Owner struct {
			ID    interface{} `json:"id"`
			Type  string      `json:"type"`
			Email interface{} `json:"email"`
		} `json:"owner"`
		Account struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		} `json:"account"`
		Tenant struct {
			ID   interface{} `json:"id"`
			Name interface{} `json:"name"`
		} `json:"tenant"`
		TenantUnit struct {
			ID interface{} `json:"id"`
		} `json:"tenant_unit"`
		Permissions []string `json:"permissions"`
		Plan        struct {
			ID                string `json:"id"`
			Name              string `json:"name"`
			Price             int    `json:"price"`
			Currency          string `json:"currency"`
			Frequency         string `json:"frequency"`
			IsSubscribed      bool   `json:"is_subscribed"`
			CanSubscribe      bool   `json:"can_subscribe"`
			LegacyID          string `json:"legacy_id"`
			LegacyDiscount    bool   `json:"legacy_discount"`
			ExternallyManaged bool   `json:"externally_managed"`
		} `json:"plan"`
	} `json:"result"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		TotalPages int `json:"total_pages"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
	} `json:"result_info"`
	Success  bool          `json:"success"`
	Errors   []interface{} `json:"errors"`
	Messages []interface{} `json:"messages"`
}

func postToCloudflare() {
	url := "https://api.cloudflare.com/client/v4/zones"

	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + "SntWCUhue3xL-jHjR8AavjXHLUdjJYr4fI03vJQQ"

	// Create a new request using http
	req, err := http.NewRequest("GET", url, nil)

	// add authorization header to the req
	req.Header.Add("Authorization", bearer)

	// Send req using http Client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error while reading the response bytes:", err)
	}
	//var info map[string]interface{}
	var res Res
	if err := json.Unmarshal([]byte(body), &res); err != nil {
		os.Exit(1)
	}

	fmt.Printf(res)
	//fmt.Printf("Species: %s, Description: %s", res, bird.Description)
	//fmt.Println(info.Result["name"])

	return
	//log.Println(string([]byte(body)))
	//log.Println()
}

func genCloudflareReq(certfile string, port string, protocol string) string {
	currentTime := time.Now()

	data := Data{
		Usage:        3,
		Selector:     1,
		Matchingtype: 1,
		Certificate:  getSHA256sum(certfile),
	}

	jsonRequest := JSONRequest{
		Type:     "TLSA",
		Name:     "_" + port + "._" + protocol + ".test",
		Data:     data,
		Ttl:      3600,
		Priority: 10,
		Proxied:  false,
		Comment:  "Created by GoTLSAFlare - " + currentTime.Format("2006-01-02 15:04:05"),
	}

	byteArray, err := json.MarshalIndent(jsonRequest, "", "  ")

	if err != nil {
		fmt.Println(err)
	}
	return string(byteArray)
}

func getSHA256sum(certfile string) string {
	pemContent, err := os.ReadFile(certfile)
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
	createTLSA := flag.Bool("create", false, "Create TLSA Record")
	updateTLSA := flag.Bool("update", false, "Update TLSA Record")
	port25tcp := flag.Bool("25tcp", false, "Port 25/TCP")
	port465tcp := flag.Bool("465tcp", false, "Port 465/TCP")
	port587tcp := flag.Bool("587tcp", false, "Port 587/TCP")
	certfile := flag.String("cert", "", "Certificate File")

	flag.Parse()

	switch {
	case *port25tcp:
		var certfilez string = *certfile
		if *createTLSA {
			fmt.Println(genCloudflareReq(certfilez, "25", "tcp"))
		} else if *updateTLSA {
			fmt.Print("lol")
		}
		return
	case *port465tcp:
		var certfilez string = *certfile
		if *createTLSA {
			fmt.Println(genCloudflareReq(certfilez, "465", "tcp"))
		} else if *updateTLSA {
			fmt.Print("lol")
		}
		return
	case *port587tcp:
		var certfilez string = *certfile
		if *createTLSA {
			fmt.Println(genCloudflareReq(certfilez, "587", "tcp"))
		} else if *updateTLSA {
			fmt.Print("lol")
		}
		return
	}

	postToCloudflare()
	fmt.Println("lol")
}
