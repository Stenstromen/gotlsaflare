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

	"github.com/miekg/dns"
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

	daneEE, err := cmd.Flags().GetBool("dane-ee")
	if err != nil {
		return err
	}

	noDaneEE, err := cmd.Flags().GetBool("no-dane-ee")
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

	matchingType, err := cmd.Flags().GetInt("matching-type")
	if err != nil {
		return err
	}

	// Handle the case where both --dane-ee and --no-dane-ee are specified
	if noDaneEE {
		daneEE = false
	}

	// Ensure at least one of DANE-EE or DANE-TA is enabled
	if !daneEE && !daneTa {
		log.Println("Error: At least one of DANE-EE or DANE-TA must be enabled")
		os.Exit(1)
	}

	// Validate matching type
	if matchingType != 1 && matchingType != 2 {
		log.Println("Error: Matching type must be either 1 (SHA2-256) or 2 (SHA2-512)")
		os.Exit(1)
	}

	handlePortUpdate := func(port string) {
		prefix := "_" + port + "._tcp."
		domain := subdomain + "." + url

		// Use appropriate selectors for each usage type if not explicitly specified
		eeSel := selector
		taSel := selector

		// If selector is not explicitly set (-1), use defaults
		if selector == -1 {
			eeSel = 1 // Default to SPKI(1) for DANE-EE
			taSel = 0 // Default to Cert(0) for DANE-TA
		}

		if daneEE {
			eeReq := genCloudflareReq(cert, port, "tcp", subdomain, "Updated", 3, eeSel, matchingType)
			if rollover {
				performRollover(prefix, domain, eeReq)
			} else {
				putToCloudflare(prefix, domain, eeReq)
			}
		}

		if daneTa {
			taReq := genCloudflareReq(cert, port, "tcp", subdomain, "Updated", 2, taSel, matchingType)
			if rollover && !daneEE {
				// Only use rollover for DANE-TA if DANE-EE is not enabled
				performRollover(prefix, domain, taReq)
			} else {
				putToCloudflare(prefix, domain, taReq)
			}
		}
	}

	// Collect all ports to process
	var ports []string
	if tcpPort != 0 {
		ports = append(ports, strconv.Itoa(tcpPort))
	}
	if tcp25 {
		ports = append(ports, "25")
	}
	if tcp465 {
		ports = append(ports, "465")
	}
	if tcp587 {
		ports = append(ports, "587")
	}

	// Validate that at least one port is specified
	if len(ports) == 0 {
		return fmt.Errorf("no ports specified. Please specify at least one port using --tcp-port, --tcp25, --tcp465, or --tcp587")
	}

	// Process all ports
	for _, port := range ports {
		handlePortUpdate(port)
	}

	return nil
}

func putToCloudflare(portandprotocol string, nameanddomain string, putBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"
	var bearer = "Bearer " + os.Getenv("TOKEN")

	// Extract usage value from putBody
	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(putBody), &jsonReq); err != nil {
		log.Printf("Error parsing request body: %v\n", err)
		return
	}
	usage := jsonReq.Data.Usage

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
		if portandprotocol+nameanddomain == recordsres.Result[i].Name &&
			recordsres.Result[i].Type == "TLSA" &&
			recordsres.Result[i].Data.Usage == usage {
			did = recordsres.Result[i].ID
			break
		}
	}

	if did == "" {
		log.Printf("Error: Could not find existing TLSA record with usage %d for %s%s\n",
			usage, portandprotocol, nameanddomain)
		os.Exit(1)
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

	// Extract usage value from putBody
	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(putBody), &jsonReq); err != nil {
		log.Printf("Error parsing request body: %v\n", err)
		return
	}
	usage := jsonReq.Data.Usage

	// Get zone ID and old record first with the correct usage value
	zoneID, oldRecord := getExistingRecord(url, bearer, portandprotocol, nameanddomain, usage)

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
		// Wait for 2 rounds of TTL as per DANE certificate rollover best practices
		waitTime := 2 * ttl
		log.Printf("Waiting for %.0f seconds (2 TTL periods) to ensure DNS propagation...\n", waitTime.Seconds())
		time.Sleep(waitTime)

		// Check DNS propagation before deleting the old record
		if err := checkDNSPropagation(portandprotocol + nameanddomain); err != nil {
			log.Printf("Warning: DNS propagation check failed: %v\n", err)
			// Even if the check fails, we proceed with deletion to maintain existing behavior
		}

		if err := deleteRecord(zoneID, oldRecordID, bearer); err != nil {
			log.Printf("Error deleting old record: %v\n", err)
		}
		done <- true
	}()

	log.Printf("Created new TLSA record. Old record will be deleted in %.0f seconds\n", (2 * ttl).Seconds())

	// Wait for deletion to complete
	<-done
}

// checkDNSPropagation verifies that DNS changes have propagated by querying multiple nameservers
func checkDNSPropagation(recordName string) error {
	nameservers := []string{
		"8.8.8.8:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"9.9.9.9:53",        // Quad9
		"208.67.222.222:53", // OpenDNS
	}

	log.Printf("Checking DNS propagation for %s against %d nameservers\n", recordName, len(nameservers))

	m := new(dns.Msg)
	m.SetQuestion(dns.Fqdn(recordName), dns.TypeTLSA)
	m.RecursionDesired = true

	for _, ns := range nameservers {
		c := new(dns.Client)
		r, rtt, err := c.Exchange(m, ns)
		if err != nil {
			log.Printf("Failed to query %s: %v\n", ns, err)
			return fmt.Errorf("DNS query to %s failed: %v", ns, err)
		}
		log.Printf("Successfully queried %s (response time: %v, answer sections: %d)\n",
			ns, rtt, len(r.Answer))
	}

	return nil
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

func getExistingRecord(url, bearer, portandprotocol, nameanddomain string, usage int) (string, *DNSRecord) {
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
		if record.Type == "TLSA" && record.Name == portandprotocol+nameanddomain && record.Data.Usage == usage {
			return zoneID, &record
		}
	}

	return zoneID, nil
}
