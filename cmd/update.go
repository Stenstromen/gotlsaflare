package cmd

import (
	"gotlsaflare/resource"

	"github.com/spf13/cobra"
)

var updateCmd = &cobra.Command{
	Use:   "update",
	Short: "Update TLSA DNS Record",
	Long:  `Update TLSA DNS Record`,
	RunE:  resource.ResourceUpdate,
}

func init() {
	rootCmd.AddCommand(updateCmd)
	updateCmd.Flags().StringP("url", "u", "", "Domain to Update (Required)")
	updateCmd.Flags().StringP("subdomain", "s", "", "TLSA Subdomain (Required)")
	updateCmd.Flags().StringP("cert", "f", "", "Path to Certificate File (Required)")
	updateCmd.Flags().BoolP("tcp25", "t", true, "Port 25/TCP")
	updateCmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	updateCmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	updateCmd.MarkFlagRequired("url")
	updateCmd.MarkFlagRequired("subdomain")
	updateCmd.MarkFlagRequired("cert")
}
