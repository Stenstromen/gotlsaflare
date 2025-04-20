package resource

import (
	"bytes"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"

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

	tcpPort, err := cmd.Flags().GetInt("tcp-port")
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

	createTLSARecords := func(port string) {
		// Use appropriate selectors for each usage type if not explicitly specified
		eeSel := selector
		taSel := selector

		// If selector is not explicitly set (-1), use defaults
		if selector == -1 {
			eeSel = 1 // Default to SPKI(1) for DANE-EE
			taSel = 0 // Default to Cert(0) for DANE-TA
		}

		if daneEE {
			postToCloudflare("_"+port+"._tcp.", url, genCloudflareReq(cert, port, "tcp", subdomain, "Created", 3, eeSel, matchingType))
		}

		if daneTa {
			postToCloudflare("_"+port+"._tcp.", url, genCloudflareReq(cert, port, "tcp", subdomain, "Created", 2, taSel, matchingType))
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
		createTLSARecords(port)
	}

	return nil
}

func postToCloudflare(portandprotocol string, nameanddomain string, postBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"
	bearer := "Bearer " + os.Getenv("TOKEN")
	// First check if record exists with either usage type (2 for DANE-TA or 3 for DANE-EE)
	zoneID, existingRecordEE, err := getExistingRecord(url, bearer, portandprotocol, nameanddomain, 3)
	if err != nil {
		log.Printf("Error checking for existing DANE-EE record: %v\n", err)
		os.Exit(1)
	}

	_, existingRecordTA, err := getExistingRecord(url, bearer, portandprotocol, nameanddomain, 2)
	if err != nil {
		log.Printf("Error checking for existing DANE-TA record: %v\n", err)
		os.Exit(1)
	}

	if existingRecordEE != nil || existingRecordTA != nil {
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
