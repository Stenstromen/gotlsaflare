package cmd

import (
	"gotlsaflare/resource"

	"github.com/spf13/cobra"
)

var verifyCmd = &cobra.Command{
	Use:          "verify",
	Short:        "Verify TLSA DNS records against a certificate",
	SilenceUsage: true,
	Long: `Verify published TLSA records against a certificate.

With --cert, hashes are computed from the local PEM file.
Without --cert, the endpoint is connected and the presented chain is hashed.
Ports 25 and 587 use SMTP STARTTLS unless --starttls is set.
DNS is always queried for the TLSA owner name _port._tcp.host.

DANE-EE (3 1 1) hashes the end-entity SubjectPublicKeyInfo with SHA2-256.
DANE-TA (2 0 1) hashes the last certificate in the chain with SHA2-256.
A check succeeds when any published TLSA record of that type matches, so a
rollover record still verifies.`,
	RunE: resource.ResourceVerify,
}

func init() {
	rootCmd.AddCommand(verifyCmd)
	verifyCmd.Flags().StringP("url", "u", "", "Domain (Required)")
	verifyCmd.Flags().StringP("subdomain", "s", "", "TLSA subdomain (Required)")
	verifyCmd.Flags().StringP("cert", "f", "", "Certificate PEM. Full chain when checking DANE-TA. Omit to connect to the endpoint")
	verifyCmd.Flags().BoolP("tcp25", "t", false, "Port 25/TCP")
	verifyCmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	verifyCmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	verifyCmd.Flags().IntP("tcp-port", "c", 0, "Custom TCP Port")
	verifyCmd.Flags().BoolP("dane-ee", "", true, "Verify DANE-EE (3 1 1) record")
	verifyCmd.Flags().BoolP("no-dane-ee", "", false, "Do not verify DANE-EE (use with --dane-ta)")
	verifyCmd.Flags().BoolP("dane-ta", "", false, "Verify DANE-TA (2 0 1) record")
	verifyCmd.Flags().IntP("selector", "l", -1, "TLSA selector (0 = Full cert, 1 = SubjectPublicKeyInfo). If not specified, defaults to 1 for DANE-EE and 0 for DANE-TA")
	verifyCmd.Flags().IntP("matching-type", "m", 1, "TLSA matching type (1 = SHA2-256, 2 = SHA2-512)")
	verifyCmd.Flags().String("starttls", "auto", "Connect handshake: auto (STARTTLS on 25 and 587), smtp, or tls")
	verifyCmd.MarkFlagRequired("url")
	verifyCmd.MarkFlagRequired("subdomain")
}
