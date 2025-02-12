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

func init() {
	rootCmd.AddCommand(createCmd)
	createCmd.Flags().StringP("url", "u", "", "Domain to Update (Required)")
	createCmd.Flags().StringP("subdomain", "s", "", "TLSA Subdomain (Required)")
	createCmd.Flags().StringP("cert", "f", "", "Path to Certificate File, fullchain if dane-ta is true (Required)")
	createCmd.Flags().BoolP("tcp25", "t", true, "Port 25/TCP")
	createCmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	createCmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	createCmd.Flags().BoolP("dane-ta", "", false, "Create DANE-TA (2 1 1) record")
	createCmd.MarkFlagRequired("url")
	createCmd.MarkFlagRequired("subdomain")
	createCmd.MarkFlagRequired("cert")
}
