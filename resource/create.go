package resource

import (
	"bytes"
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

	// Handle the case where both --dane-ee and --no-dane-ee are specified
	if noDaneEE {
		daneEE = false
	}

	// Ensure at least one of DANE-EE or DANE-TA is enabled
	if !daneEE && !daneTa {
		log.Println("Error: At least one of DANE-EE or DANE-TA must be enabled")
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
			postToCloudflare("_"+port+"._tcp.", url, genCloudflareReq(cert, port, "tcp", subdomain, "Created", 3, eeSel))
		}

		if daneTa {
			postToCloudflare("_"+port+"._tcp.", url, genCloudflareReq(cert, port, "tcp", subdomain, "Created", 2, taSel))
		}
	}

	if tcpPort != 0 {
		createTLSARecords(strconv.Itoa(tcpPort))
	}

	if tcp25 {
		createTLSARecords("25")
	}
	if tcp465 {
		createTLSARecords("465")
	}
	if tcp587 {
		createTLSARecords("587")
	}

	return nil
}

func postToCloudflare(portandprotocol string, nameanddomain string, postBody string) {
	url := "https://api.cloudflare.com/client/v4/zones"
	bearer := "Bearer " + os.Getenv("TOKEN")

	// First check if record exists with either usage type (2 for DANE-TA or 3 for DANE-EE)
	zoneID, existingRecordEE := getExistingRecord(url, bearer, portandprotocol, nameanddomain, 3)
	_, existingRecordTA := getExistingRecord(url, bearer, portandprotocol, nameanddomain, 2)

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
