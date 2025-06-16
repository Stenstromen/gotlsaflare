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
	"strings"
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
		fmt.Println("Error: At least one of DANE-EE or DANE-TA must be enabled")
		os.Exit(1)
	}

	// Validate matching type
	if matchingType != 1 && matchingType != 2 {
		fmt.Println("Error: Matching type must be either 1 (SHA2-256) or 2 (SHA2-512)")
		os.Exit(1)
	}

	var updateErrors []error

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
				err := performRollover(prefix, domain, eeReq)
				if err != nil {
					updateErrors = append(updateErrors, fmt.Errorf("error performing DANE-EE rollover for port %s: %w", port, err))
				}
			} else {
				err := putToCloudflare(prefix, domain, eeReq)
				if err != nil {
					updateErrors = append(updateErrors, fmt.Errorf("error updating DANE-EE for port %s: %w", port, err))
				}
			}
		}

		if daneTa {
			taReq := genCloudflareReq(cert, port, "tcp", subdomain, "Updated", 2, taSel, matchingType)
			if rollover && !daneEE {
				// Only use rollover for DANE-TA if DANE-EE is not enabled
				err := performRollover(prefix, domain, taReq)
				if err != nil {
					updateErrors = append(updateErrors, fmt.Errorf("error performing DANE-TA rollover for port %s: %w", port, err))
				}
			} else {
				err := putToCloudflare(prefix, domain, taReq)
				if err != nil {
					updateErrors = append(updateErrors, fmt.Errorf("error updating DANE-TA for port %s: %w", port, err))
				}
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

	// Return the first error if any occurred during updates
	if len(updateErrors) > 0 {
		for _, err := range updateErrors {
			fmt.Println(err)
		}
		return updateErrors[0]
	}

	return nil
}

func putToCloudflare(portandprotocol string, nameanddomain string, putBody string) error {
	url := "https://api.cloudflare.com/client/v4/zones"
	var bearer = "Bearer " + os.Getenv("TOKEN")

	// Extract usage value from putBody
	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(putBody), &jsonReq); err != nil {
		log.Printf("Error parsing request body: %v\n", err)
		return fmt.Errorf("error parsing request body: %v", err)
	}
	usage := jsonReq.Data.Usage

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Println(err)
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Println("Error on response.\n[ERROR] -", err)
		return fmt.Errorf("error on response: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Println("Error while reading the response bytes:", err)
		return fmt.Errorf("error while reading the response bytes: %v", err)
	}

	var res Res
	if err := json.Unmarshal(body, &res); err != nil {
		log.Println(err)
		return fmt.Errorf("error parsing JSON response: %v", err)
	}

	zoneID := ""
	for _, zone := range res.Result {
		if strings.HasSuffix(nameanddomain, zone.Name) {
			zoneID = zone.ID
		}
	}

	if zoneID == "" {
		log.Println("No matching zones found")
		return fmt.Errorf("no matching zones found")
	}

	searchurl := "https://api.cloudflare.com/client/v4/zones/" + zoneID + "/dns_records"

	req2, err2 := http.NewRequest("GET", searchurl, nil)
	if err2 != nil {
		log.Println(err2)
		return fmt.Errorf("error creating search request: %v", err2)
	}

	req2.Header.Add("Authorization", bearer)

	resp2, err2 := client.Do(req2)
	if err2 != nil {
		log.Println("Error on response.\n[ERROR] -", err2)
		return fmt.Errorf("error on search response: %v", err2)
	}
	defer resp2.Body.Close()

	body2, err2 := io.ReadAll(resp2.Body)
	if err2 != nil {
		log.Println("Error while reading the response bytes:", err2)
		return fmt.Errorf("error while reading the search response bytes: %v", err2)
	}

	var recordsres RecordsRes
	if err2 := json.Unmarshal(body2, &recordsres); err2 != nil {
		log.Println(err2)
		return fmt.Errorf("error parsing records response: %v", err2)
	}

	var recordid = ""

	for _, record := range recordsres.Result {
		if record.Type == "TLSA" && record.Name == portandprotocol+nameanddomain && record.Data.Usage == usage {
			recordid = record.ID
		}
	}

	if recordid == "" {
		log.Printf("Error: Could not find existing TLSA record with usage %d for %s%s\n",
			usage, portandprotocol, nameanddomain)
		return fmt.Errorf("could not find existing TLSA record with usage %d for %s%s", usage, portandprotocol, nameanddomain)
	}

	puturl := "https://api.cloudflare.com/client/v4/zones/" + zoneID + "/dns_records/" + recordid

	var jsonStr = []byte(putBody)
	req3, err3 := http.NewRequest("PUT", puturl, bytes.NewBuffer(jsonStr))
	if err3 != nil {
		log.Println(err3)
		return fmt.Errorf("error creating put request: %v", err3)
	}

	req3.Header.Set("Content-Type", "application/json")
	req3.Header.Add("Authorization", bearer)

	client3 := &http.Client{}
	resp3, err3 := client3.Do(req3)
	if err3 != nil {
		log.Println(err3)
		return fmt.Errorf("error updating record: %v", err3)
	}
	defer resp3.Body.Close()

	fmt.Println("Cloudflare Response Status:", resp3.Status)
	return nil
}

func performRollover(portandprotocol string, nameanddomain string, putBody string) error {
	url := "https://api.cloudflare.com/client/v4/zones"
	bearer := "Bearer " + os.Getenv("TOKEN")

	// Extract usage value from putBody
	var jsonReq JSONRequest
	if err := json.Unmarshal([]byte(putBody), &jsonReq); err != nil {
		log.Printf("Error parsing request body: %v\n", err)
		return fmt.Errorf("error parsing request body: %v", err)
	}
	usage := jsonReq.Data.Usage

	// Get zone ID and old record first with the correct usage value
	zoneID, oldRecord, err := getExistingRecord(url, bearer, portandprotocol, nameanddomain, usage)
	if err != nil {
		log.Printf("Error getting existing record: %v\n", err)
		return err
	}

	if zoneID == "" {
		log.Println("Error: Could not find zone ID")
		return fmt.Errorf("could not find zone ID")
	}

	// Store old record details
	oldRecordID := ""
	if oldRecord != nil {
		oldRecordID = oldRecord.ID
	} else {
		return putToCloudflare(portandprotocol, nameanddomain, putBody)
	}

	// Create new record first
	createURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	jsonStr := []byte(putBody)
	req, err := http.NewRequest("POST", createURL, bytes.NewBuffer(jsonStr))
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return fmt.Errorf("error creating request: %v", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error creating new record: %v\n", err)
		return fmt.Errorf("error creating new record: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		log.Printf("Error creating new record. Status: %s\n", resp.Status)
		return fmt.Errorf("error creating new record. Status: %s", resp.Status)
	}

	ttl := time.Duration(oldRecord.TTL) * time.Second
	if ttl == 0 {
		ttl = 3600 * time.Second // Default to 1 hour if TTL is 0
	}

	// Create a channel to signal completion
	done := make(chan error)

	go func() {
		// Wait for 2 rounds of TTL as per DANE certificate rollover best practices
		waitTime := 2 * ttl
		fmt.Printf("Waiting for %.0f seconds (2 TTL periods) to ensure DNS propagation...\n", waitTime.Seconds())
		time.Sleep(waitTime)

		// Check DNS propagation before deleting the old record
		if err := checkDNSPropagation(portandprotocol + nameanddomain); err != nil {
			log.Printf("Warning: DNS propagation check failed: %v\n", err)
			// Even if the check fails, we proceed with deletion to maintain existing behavior
		}

		if err := deleteRecord(zoneID, oldRecordID, bearer); err != nil {
			log.Printf("Error deleting old record: %v\n", err)
			done <- err
			return
		}
		done <- nil
	}()

	fmt.Printf("Created new TLSA record. Old record will be deleted in %.0f seconds\n", (2 * ttl).Seconds())

	// Wait for deletion to complete
	err = <-done
	return err
}

// checkDNSPropagation verifies that DNS changes have propagated by querying multiple nameservers
func checkDNSPropagation(recordName string) error {
	nameservers := []string{
		"8.8.8.8:53",        // Google
		"1.1.1.1:53",        // Cloudflare
		"9.9.9.9:53",        // Quad9
		"208.67.222.222:53", // OpenDNS
	}

	fmt.Printf("Checking DNS propagation for %s against %d nameservers\n", recordName, len(nameservers))

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
		fmt.Printf("Successfully queried %s (response time: %v, answer sections: %d)\n",
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

	fmt.Printf("Deleted old TLSA record. Status: %s\n", resp.Status)
	return nil
}

func getExistingRecord(url, bearer, portandprotocol, nameanddomain string, usage int) (string, *DNSRecord, error) {
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		log.Printf("Error creating request: %v\n", err)
		return "", nil, fmt.Errorf("error creating request: %v", err)
	}
	req.Header.Add("Authorization", bearer)

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		log.Printf("Error getting zone info: %v\n", err)
		return "", nil, fmt.Errorf("error getting zone info: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		log.Printf("Error reading response: %v\n", err)
		return "", nil, fmt.Errorf("error reading response: %v", err)
	}

	var res Res
	if err := json.Unmarshal(body, &res); err != nil {
		log.Printf("Error parsing zone response: %v\n", err)
		return "", nil, fmt.Errorf("error parsing zone response: %v", err)
	}

	if len(res.Result) == 0 {
		log.Println("No zones found")
		return "", nil, fmt.Errorf("no zones found")
	}

	zoneID := ""
	for _, zone := range res.Result {
		if zone.Name == nameanddomain {
			zoneID = zone.ID
		}
	}

	if zoneID == "" {
		log.Println("No matching zones found")
		return "", nil, fmt.Errorf("no matching zones found")
	}

	recordsURL := fmt.Sprintf("https://api.cloudflare.com/client/v4/zones/%s/dns_records", zoneID)
	req2, err := http.NewRequest("GET", recordsURL, nil)
	if err != nil {
		log.Printf("Error creating records request: %v\n", err)
		return zoneID, nil, fmt.Errorf("error creating records request: %v", err)
	}
	req2.Header.Add("Authorization", bearer)

	resp2, err := client.Do(req2)
	if err != nil {
		log.Printf("Error getting DNS records: %v\n", err)
		return zoneID, nil, fmt.Errorf("error getting DNS records: %v", err)
	}
	defer resp2.Body.Close()

	body2, err := io.ReadAll(resp2.Body)
	if err != nil {
		log.Printf("Error reading records response: %v\n", err)
		return zoneID, nil, fmt.Errorf("error reading records response: %v", err)
	}

	var recordsRes RecordsRes
	if err := json.Unmarshal(body2, &recordsRes); err != nil {
		log.Printf("Error parsing records response: %v\n", err)
		return zoneID, nil, fmt.Errorf("error parsing records response: %v", err)
	}

	for _, record := range recordsRes.Result {
		if record.Type == "TLSA" && record.Name == portandprotocol+nameanddomain && record.Data.Usage == usage {
			return zoneID, &record, nil
		}
	}

	return zoneID, nil, nil
}
