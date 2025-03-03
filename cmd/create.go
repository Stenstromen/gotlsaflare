package cmd

import (
	"gotlsaflare/resource"

	"github.com/spf13/cobra"
)

var createCmd = &cobra.Command{
	Use:   "create",
	Short: "Create TLSA DNS Record",
	Long:  `Create TLSA DNS Record`,
	RunE:  resource.ResourceCreate,
}

func addCommonFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("url", "u", "", "Domain to Update (Required)")
	cmd.Flags().StringP("subdomain", "s", "", "TLSA Subdomain (Required)")
	cmd.Flags().StringP("cert", "f", "", "Path to Certificate File, fullchain if dane-ta is true (Required)")
	cmd.Flags().BoolP("tcp25", "t", false, "Port 25/TCP")
	cmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	cmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	cmd.Flags().IntP("tcp-port", "c", 0, "Custom TCP Port")
	cmd.Flags().BoolP("dane-ee", "", true, "Create DANE-EE (3 1 1) record")
	cmd.Flags().BoolP("no-dane-ee", "", false, "Do not create DANE-EE record (use with --dane-ta)")
	cmd.Flags().BoolP("dane-ta", "", false, "Create DANE-TA (2 0 1) record")
	cmd.Flags().IntP("selector", "l", -1, "TLSA selector (0 = Full cert, 1 = SubjectPublicKeyInfo). If not specified, defaults to 1 for DANE-EE and 0 for DANE-TA")
	cmd.Flags().IntP("matching-type", "m", 1, "TLSA matching type (1 = SHA2-256, 2 = SHA2-512)")
	cmd.MarkFlagRequired("url")
	cmd.MarkFlagRequired("subdomain")
	cmd.MarkFlagRequired("cert")
}

func init() {
	rootCmd.AddCommand(createCmd)
	addCommonFlags(createCmd)
}
