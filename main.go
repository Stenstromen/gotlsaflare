package main

import (
	"bytes"
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

type RecordsRes struct {
	Result []struct {
		ID        string `json:"id"`
		ZoneID    string `json:"zone_id"`
		ZoneName  string `json:"zone_name"`
		Name      string `json:"name"`
		Type      string `json:"type"`
		Content   string `json:"content"`
		Proxiable bool   `json:"proxiable"`
		Proxied   bool   `json:"proxied"`
		TTL       int    `json:"ttl"`
		Locked    bool   `json:"locked"`
		Data      struct {
			Certificate  string `json:"certificate"`
			MatchingType int    `json:"matching_type"`
			Selector     int    `json:"selector"`
			Usage        int    `json:"usage"`
		} `json:"data"`
		Meta struct {
			AutoAdded           bool   `json:"auto_added"`
			ManagedByApps       bool   `json:"managed_by_apps"`
			ManagedByArgoTunnel bool   `json:"managed_by_argo_tunnel"`
			Source              string `json:"source"`
		} `json:"meta"`
		Comment    string        `json:"comment"`
		Tags       []interface{} `json:"tags"`
		CreatedOn  time.Time     `json:"created_on"`
		ModifiedOn time.Time     `json:"modified_on"`
	} `json:"result"`
	Success    bool          `json:"success"`
	Errors     []interface{} `json:"errors"`
	Messages   []interface{} `json:"messages"`
	ResultInfo struct {
		Page       int `json:"page"`
		PerPage    int `json:"per_page"`
		Count      int `json:"count"`
		TotalCount int `json:"total_count"`
		TotalPages int `json:"total_pages"`
	} `json:"result_info"`
}

func postToCloudflare(postBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"

	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + os.Getenv("TOKEN")

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
	if err := json.Unmarshal(body, &res); err != nil {
		os.Exit(1)
	}

	name := "filip.com.se"
	if name != res.Result[0].Name {
		os.Exit(1)
		return
	}

	fmt.Println(res.Result[0].ID)
	fmt.Println(res.Result[0].Name)

	posturl := "https://api.cloudflare.com/client/v4/zones/" + res.Result[0].ID + "/dns_records"
	fmt.Println(posturl)
	var jsonStr = []byte(postBody)
	req2, err2 := http.NewRequest("POST", posturl, bytes.NewBuffer(jsonStr))
	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Add("Authorization", bearer)

	client2 := &http.Client{}
	resp2, err2 := client2.Do(req2)
	if err2 != nil {
		panic(err2)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp2.Status)
	fmt.Println("response Headers:", resp2.Header)
	body2, _ := ioutil.ReadAll(resp2.Body)
	fmt.Println("response Body:", string(body2))
}

func putToCloudflare(putBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"

	// Create a Bearer string by appending string access token
	var bearer = "Bearer " + os.Getenv("TOKEN")

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
	if err := json.Unmarshal(body, &res); err != nil {
		os.Exit(1)
	}

	//fmt.Println(res.Result[0].ID)

	searchurl := "https://api.cloudflare.com/client/v4/zones/" + res.Result[0].ID + "/dns_records"
	fmt.Println(searchurl)
	req2, err2 := http.NewRequest("GET", searchurl, nil)
	req2.Header.Add("Authorization", bearer)
	client2 := &http.Client{}
	resp2, err2 := client2.Do(req2)
	if err2 != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp2.Body.Close()
	body2, err2 := ioutil.ReadAll(resp2.Body)
	if err2 != nil {
		log.Println("Error while reading the response bytes:", err)
	}
	//var info map[string]interface{}
	var recordsres RecordsRes
	if err2 := json.Unmarshal(body2, &recordsres); err2 != nil {
		os.Exit(1)
	}

	var lol string

	for i := range recordsres.Result {
		if "_25._tcp.test.filip.com.se" == recordsres.Result[i].Name {
			lol = recordsres.Result[i].ID
		}
	}

	puturl := "https://api.cloudflare.com/client/v4/zones/" + res.Result[0].ID + "/dns_records/" + lol

	fmt.Print(puturl)

	var jsonStr = []byte(putBody)
	req3, err3 := http.NewRequest("PUT", puturl, bytes.NewBuffer(jsonStr))
	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Add("Authorization", bearer)

	client3 := &http.Client{}
	resp3, err3 := client3.Do(req3)
	if err3 != nil {
		panic(err3)
	}
	defer resp.Body.Close()

	fmt.Println("response Status:", resp3.Status)
	fmt.Println("response Headers:", resp3.Header)
	body3, _ := ioutil.ReadAll(resp3.Body)
	fmt.Println("response Body:", string(body3))

	/* var identifier string

	for i := range res.Result {
		name := "filip.com.se"
		fmt.Printf(res.Result[i].Name)
		if name != res.Result[i].Name {
			return res.Result[i].ID
		}
	} */
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
			postToCloudflare(genCloudflareReq(certfilez, "25", "tcp"))
		} else if *updateTLSA {
			putToCloudflare(genCloudflareReq(certfilez, "25", "tcp"))
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

	/* postToCloudflare() */
	fmt.Println("lol")
}
