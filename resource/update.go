package resource

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/spf13/cobra"
)

func ResourceUpdate(cmd *cobra.Command, args []string) error {
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
	tcpPort, err := cmd.Flags().GetInt("tcp-port")
	if err != nil {
		return err
	}
	rollover, err := cmd.Flags().GetBool("rollover")
	if err != nil {
		return err
	}
	selector, err := cmd.Flags().GetInt("selector")
	if err != nil {
		return err
	}

	handlePortUpdate := func(port string) {
		prefix := "_" + port + "._tcp."
		domain := subdomain + "." + url
		req := genCloudflareReq(cert, port, "tcp", subdomain, "Updated", 3, selector)

		if rollover {
			performRollover(prefix, domain, req)
		} else {
			putToCloudflare(prefix, domain, req)
		}

		if daneTa {
			putToCloudflare(prefix, domain, genCloudflareReq(cert, port, "tcp", subdomain, "Updated", 2, selector))
		}
	}

	if tcpPort != 0 {
		handlePortUpdate(strconv.Itoa(tcpPort))
	}

	if tcp25 {
		handlePortUpdate("25")
	}
	if tcp465 {
		handlePortUpdate("465")
	}
	if tcp587 {
		handlePortUpdate("587")
	}

	return nil
}

func putToCloudflare(portandprotocol string, nameanddomain string, putBody string) {
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

	searchurl := "https://api.cloudflare.com/client/v4/zones/" + res.Result[0].ID + "/dns_records"
	req2, err2 := http.NewRequest("GET", searchurl, nil)
	if err2 != nil {
		log.Println(err2)
		os.Exit(1)
	}

	req2.Header.Add("Authorization", bearer)
	client2 := &http.Client{}
	resp2, err2 := client2.Do(req2)
	if err2 != nil {
		log.Println("Error on response.\n[ERROR] -", err)
	}
	defer resp2.Body.Close()
	body2, err2 := io.ReadAll(resp2.Body)
	if err2 != nil {
		log.Println("Error while reading the response bytes:", err)
	}

	var recordsres RecordsRes
	if err2 := json.Unmarshal(body2, &recordsres); err2 != nil {
		log.Println(err2)
		os.Exit(1)
	}

	var did string

	for i := range recordsres.Result {
		if portandprotocol+nameanddomain == recordsres.Result[i].Name {
			did = recordsres.Result[i].ID

		}
	}

	puturl := "https://api.cloudflare.com/client/v4/zones/" + res.Result[0].ID + "/dns_records/" + did

	var jsonStr = []byte(putBody)
	req3, err3 := http.NewRequest("PUT", puturl, bytes.NewBuffer(jsonStr))
	if err3 != nil {
		log.Println(err3)
		os.Exit(1)
	}

	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Add("Authorization", bearer)

	client3 := &http.Client{}
	resp3, err3 := client3.Do(req3)
	if err3 != nil {
		log.Println(err3)
		os.Exit(1)
	}
	defer resp.Body.Close()

	log.Println("Cloudflare Response Status:", resp3.Status)
}

func performRollover(portandprotocol string, nameanddomain string, putBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"
	bearer := "Bearer " + os.Getenv("TOKEN")

	// Get zone ID and old record first
	zoneID, oldRecord := getExistingRecord(url, bearer, portandprotocol, nameanddomain)

	if zoneID == "" {
		log.Println("Error: Could not find zone ID")
		return
	}

	// Store old record details
	oldRecordID := ""
	if oldRecord != nil {
		oldRecordID = oldRecord.ID
	} else {
		putToCloudflare(portandprotocol, nameanddomain, putBody)
		return
	}

	// Create new record first
	createURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	jsonStr := []byte(putBody)
	req, err := http.NewRequest("POST", createURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error creating new record: %v\n", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Error creating new record. Status: %s\n", resp.Status)
		return
	}

	ttl := time.Duration(oldRecord.TTL) * time.Second
	if ttl == 0 {
		ttl = 3600 * time.Second // Default to 1 hour if TTL is 0
	}

	// Create a channel to signal completion
	done := make(chan bool)

	go func() {
		time.Sleep(ttl)
		if err := deleteRecord(zoneID, oldRecordID, bearer); err != nil {
			log.Printf("Error deleting old record: %v\n", err)
		}
		done <- true
	}()

	log.Printf("Created new TLSA record. Old record will be deleted in %.0f seconds\n", ttl.Seconds())

	// Wait for deletion to complete
	<-done
}

func deleteRecord(zoneID, recordID, bearer string) error {
	if zoneID == "" || recordID == "" {
		return fmt.Errorf("invalid zoneID or recordID")
	}

	deleteURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records/%s", zoneID, recordID)
	req, err := http.NewRequest("DELETE", deleteURL, nil)
	if err != nil {
		return fmt.Errorf("error creating delete request: %v", err)
	}

	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error deleting record: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("delete request failed with status: %s", resp.Status)
	}

	log.Printf("Deleted old TLSA record. Status: %s\n", resp.Status)
	return nil
}

func getExistingRecord(url, bearer, portandprotocol, nameanddomain string) (string, *DNSRecord) {
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error getting zone info: %v\n", err)
		return "", nil
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	var res Res
	if err := json.Unmarshal(body, &res); err != nil {
		log.Printf("Error parsing zone response: %v\n", err)
		return "", nil
	}

	if len(res.Result) == 0 {
		log.Println("No zones found")
		return "", nil
	}

	zoneID := res.Result[0].ID

	recordsURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	req2, _ := http.NewRequest("GET", recordsURL, nil)
	req2.Header.Add("Authorization", bearer)

	resp2, err := client.Do(req2)
	if err != nil {
		log.Printf("Error getting DNS records: %v\n", err)
		return zoneID, nil
	}
	defer resp2.Body.Close()

	body2, _ := io.ReadAll(resp2.Body)
	var recordsRes RecordsRes
	if err := json.Unmarshal(body2, &recordsRes); err != nil {
		log.Printf("Error parsing records response: %v\n", err)
		return zoneID, nil
	}

	for _, record := range recordsRes.Result {
		if record.Type == "TLSA" && record.Name == portandprotocol+nameanddomain {
			return zoneID, &record
		}
	}

	return zoneID, nil
}
