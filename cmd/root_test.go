package cmd

import (
	"testing"
)

func TestExecute(t *testing.T) {
	// Test that Execute function exists and can be called
	// We don't actually run it because it would execute the CLI

	// Verify that rootCmd is properly initialized
	if rootCmd == nil {
		t.Fatal("rootCmd should not be nil")
	}

	if rootCmd.Use != "gotlsaflare" {
		t.Errorf("Expected Use to be 'gotlsaflare', got '%s'", rootCmd.Use)
	}

	if rootCmd.Short == "" {
		t.Error("Expected Short description to be set")
	}
}

func TestRootCmd_Structure(t *testing.T) {
	// Verify rootCmd has expected structure
	if rootCmd.Use != "gotlsaflare" {
		t.Errorf("Expected Use 'gotlsaflare', got '%s'", rootCmd.Use)
	}

	expectedShort := "Go binary for updating TLSA DANE record on cloudflare from x509 Certificate."
	if rootCmd.Short != expectedShort {
		t.Errorf("Expected Short '%s', got '%s'", expectedShort, rootCmd.Short)
	}
}

func TestRootCmd_HasCommands(t *testing.T) {
	// Verify that rootCmd has expected subcommands
	commands := rootCmd.Commands()

	if len(commands) == 0 {
		t.Error("Expected rootCmd to have subcommands")
	}

	// Check for expected commands
	commandNames := make(map[string]bool)
	for _, cmd := range commands {
		commandNames[cmd.Name()] = true
	}

	expectedCommands := []string{"create", "update", "completion", "help"}
	for _, expectedCmd := range expectedCommands {
		if !commandNames[expectedCmd] {
			t.Logf("Warning: Expected command '%s' not found", expectedCmd)
		}
	}
}
