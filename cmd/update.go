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
	addCommonFlags(updateCmd)
}
