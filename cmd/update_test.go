package cmd

import (
	"testing"
)

func TestUpdateCmd_Structure(t *testing.T) {
	if updateCmd == nil {
		t.Fatal("updateCmd should not be nil")
	}

	if updateCmd.Use != "update" {
		t.Errorf("Expected Use 'update', got '%s'", updateCmd.Use)
	}

	if updateCmd.Short != "Update TLSA DNS Record" {
		t.Errorf("Expected Short 'Update TLSA DNS Record', got '%s'", updateCmd.Short)
	}

	if updateCmd.RunE == nil {
		t.Error("Expected RunE to be set")
	}
}

func TestUpdateCmd_Flags(t *testing.T) {
	// Test that expected flags exist
	expectedFlags := []string{
		"url",
		"subdomain",
		"cert",
		"tcp25",
		"tcp465",
		"tcp587",
		"tcp-port",
		"dane-ee",
		"no-dane-ee",
		"dane-ta",
		"rollover",
		"selector",
		"matching-type",
	}

	for _, flagName := range expectedFlags {
		flag := updateCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag '%s' to exist", flagName)
		}
	}
}

func TestUpdateCmd_RolloverFlag(t *testing.T) {
	// Test that rollover flag exists and is boolean
	flag := updateCmd.Flags().Lookup("rollover")
	if flag == nil {
		t.Fatal("rollover flag not found")
	}

	if flag.Value.Type() != "bool" {
		t.Errorf("Expected rollover flag to be boolean, got %s", flag.Value.Type())
	}
}

func TestUpdateCmd_HasCommonFlags(t *testing.T) {
	// Verify update command has all common flags
	commonFlags := []string{"url", "subdomain", "cert", "tcp25", "tcp465", "tcp587", "tcp-port"}

	for _, flagName := range commonFlags {
		if updateCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Update command missing common flag '%s'", flagName)
		}
	}
}
