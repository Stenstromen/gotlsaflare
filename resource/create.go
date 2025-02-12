package resource

import (
	"bytes"
	"encoding/json"
	"io"
	"log"
	"net/http"
	"os"

	"github.com/spf13/cobra"
)

func ResourceCreate(cmd *cobra.Command, args []string) error {
	url, err := cmd.Flags().GetString("url")
	if err != nil {
		return err
	}
	subdomain, err := cmd.Flags().GetString("subdomain")
	if err != nil {
		return err
	}
	cert, err := cmd.Flags().GetString("cert")
	if err != nil {
		return err
	}
	tcp25, err := cmd.Flags().GetBool("tcp25")
	if err != nil {
		return err
	}
	tcp465, err := cmd.Flags().GetBool("tcp465")
	if err != nil {
		return err
	}
	tcp587, err := cmd.Flags().GetBool("tcp587")
	if err != nil {
		return err
	}
	daneTa, err := cmd.Flags().GetBool("dane-ta")
	if err != nil {
		return err
	}

	if tcp25 {
		postToCloudflare("_25._tcp.", url, genCloudflareReq(cert, "25", "tcp", subdomain, "Created", 3))
		if daneTa {
			postToCloudflare("_25._tcp.", url, genCloudflareReq(cert, "25", "tcp", subdomain, "Created", 2))
		}
	}
	if tcp465 {
		postToCloudflare("_465._tcp.", url, genCloudflareReq(cert, "465", "tcp", subdomain, "Created", 3))
		if daneTa {
			postToCloudflare("_465._tcp.", url, genCloudflareReq(cert, "465", "tcp", subdomain, "Created", 2))
		}
	}
	if tcp587 {
		postToCloudflare("_587._tcp.", url, genCloudflareReq(cert, "587", "tcp", subdomain, "Created", 3))
		if daneTa {
			postToCloudflare("_587._tcp.", url, genCloudflareReq(cert, "587", "tcp", subdomain, "Created", 2))
		}
	}

	return nil
}

func postToCloudflare(_ string, nameanddomain string, postBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"
	var bearer = "Bearer " + os.Getenv("TOKEN")
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		os.Exit(1)
	}

	req.Header.Add("Authorization", bearer)
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error while reading the response bytes:", err)
	}
	var res Res
	if err := json.Unmarshal(body, &res); err != nil {
		log.Println(err)
		os.Exit(1)
	}

	var did string

	for i := range res.Result {
		if nameanddomain == res.Result[i].Name {
			did = res.Result[i].ID
		}
	}

	posturl := "https://api.cloudflare.com/client/v4/zones/" + did + "/dns_records"
	var jsonStr = []byte(postBody)
	req2, err2 := http.NewRequest("POST", posturl, bytes.NewBuffer(jsonStr))
	if err2 != nil {
		log.Println(err2)
		os.Exit(1)
	}

	req2.Header.Set("Content-Type", "application/json")
	req2.Header.Add("Authorization", bearer)

	client2 := &http.Client{}
	resp2, err2 := client2.Do(req2)
	if err2 != nil {
		log.Println(err2)
		os.Exit(1)
	}
	defer resp.Body.Close()

	log.Println("Cloudflare Response Status:", resp2.Status)
}
