package main

import (
	"flag"
	"fmt"
)

func main() {
	fqdn := flag.String("url", "", "URL to Update or Create")
	subdomain := flag.String("subdomain", "", "TLSA Subdomain")
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
		var url string = *fqdn
		var subdomain string = *subdomain
		var suburl string = subdomain + "." + url
		if *createTLSA {
			postToCloudflare("_25._tcp.", url, genCloudflareReq(certfilez, "25", "tcp", subdomain, "Created"))
		} else if *updateTLSA {
			putToCloudflare("_25._tcp.", suburl, genCloudflareReq(certfilez, "25", "tcp", subdomain, "Updated"))
		}
		return
	case *port465tcp:
		var certfilez string = *certfile
		var url string = *fqdn
		var subdomain string = *subdomain
		var suburl string = subdomain + "." + url
		if *createTLSA {
			postToCloudflare("_465._tcp.", url, genCloudflareReq(certfilez, "465", "tcp", subdomain, "Created"))
		} else if *updateTLSA {
			putToCloudflare("_465._tcp.", suburl, genCloudflareReq(certfilez, "465", "tcp", subdomain, "Updated"))
		}
		return
	case *port587tcp:
		var certfilez string = *certfile
		var url string = *fqdn
		var subdomain string = *subdomain
		var suburl string = subdomain + "." + url
		if *createTLSA {
			postToCloudflare("_587._tcp.", url, genCloudflareReq(certfilez, "587", "tcp", subdomain, "Created"))
		} else if *updateTLSA {
			putToCloudflare("_587._tcp.", suburl, genCloudflareReq(certfilez, "587", "tcp", subdomain, "Updated"))
		}
		return
	}

	fmt.Println("- GoTLSAFlare Example Usage\n")
	fmt.Println("- Create TLSA Record")
	fmt.Println("export TOKEN=\"# Cloudflare API TOKEN\"" + "\n" + "./gotlsaflare -create -url example.com -subdomain email -25tcp -cert path/to/certificate.pem\n")
	fmt.Println("- Update TLSA Record")
	fmt.Println("export TOKEN=\"# Cloudflare API TOKEN\"" + "\n" + "./gotlsaflare -update -url example.com -subdomain email -25tcp -cert path/to/certificate.pem")
}
