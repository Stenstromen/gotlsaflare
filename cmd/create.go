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
	cmd.Flags().BoolP("tcp25", "t", true, "Port 25/TCP")
	cmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	cmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	cmd.Flags().IntP("custom-port", "c", 0, "Custom TCP Port")
	cmd.Flags().BoolP("dane-ta", "", false, "Create DANE-TA (2 1 1) record")
	cmd.MarkFlagRequired("url")
	cmd.MarkFlagRequired("subdomain")
	cmd.MarkFlagRequired("cert")
}

func init() {
	rootCmd.AddCommand(createCmd)
	addCommonFlags(createCmd)
}
