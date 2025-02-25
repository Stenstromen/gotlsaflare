package resource

import (
	"bytes"
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
	selector, err := cmd.Flags().GetInt("selector")
	if err != nil {
		return err
	}

	if tcp25 {
		postToCloudflare("_25._tcp.", url, genCloudflareReq(cert, "25", "tcp", subdomain, "Created", 3, selector))
		if daneTa {
			postToCloudflare("_25._tcp.", url, genCloudflareReq(cert, "25", "tcp", subdomain, "Created", 2, selector))
		}
	}
	if tcp465 {
		postToCloudflare("_465._tcp.", url, genCloudflareReq(cert, "465", "tcp", subdomain, "Created", 3, selector))
		if daneTa {
			postToCloudflare("_465._tcp.", url, genCloudflareReq(cert, "465", "tcp", subdomain, "Created", 2, selector))
		}
	}
	if tcp587 {
		postToCloudflare("_587._tcp.", url, genCloudflareReq(cert, "587", "tcp", subdomain, "Created", 3, selector))
		if daneTa {
			postToCloudflare("_587._tcp.", url, genCloudflareReq(cert, "587", "tcp", subdomain, "Created", 2, selector))
		}
	}

	return nil
}

func postToCloudflare(portandprotocol string, nameanddomain string, postBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"
	bearer := "Bearer " + os.Getenv("TOKEN")

	// First check if record exists
	zoneID, existingRecord := getExistingRecord(url, bearer, portandprotocol, nameanddomain)

	if existingRecord != nil {
		log.Printf("Error: TLSA record already exists for %s%s\n", portandprotocol, nameanddomain)
		os.Exit(1)
	}

	if zoneID == "" {
		log.Println("Error: Could not find zone ID")
		os.Exit(1)
	}

	posturl := "https://api.cloudflare.com/client/v4/zones/" + zoneID + "/dns_records"

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
	defer resp2.Body.Close()

	log.Println("Cloudflare Response Status:", resp2.Status)
}
