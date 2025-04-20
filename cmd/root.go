package cmd

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "gotlsaflare",
	Short: "Go binary for updating TLSA DANE record on cloudflare from x509 Certificate.",
}

func Execute() error {
	err := rootCmd.Execute()
	if err != nil {
		return err
	}
	return nil
}
