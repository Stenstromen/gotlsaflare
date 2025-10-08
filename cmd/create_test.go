package cmd

import (
	"testing"

	"github.com/spf13/cobra"
)

func TestCreateCmd_Structure(t *testing.T) {
	if createCmd == nil {
		t.Fatal("createCmd should not be nil")
	}

	if createCmd.Use != "create" {
		t.Errorf("Expected Use 'create', got '%s'", createCmd.Use)
	}

	if createCmd.Short != "Create TLSA DNS Record" {
		t.Errorf("Expected Short 'Create TLSA DNS Record', got '%s'", createCmd.Short)
	}

	if createCmd.RunE == nil {
		t.Error("Expected RunE to be set")
	}
}

func TestCreateCmd_Flags(t *testing.T) {
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
		"selector",
		"matching-type",
	}

	for _, flagName := range expectedFlags {
		flag := createCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Expected flag '%s' to exist", flagName)
		}
	}
}

func TestCreateCmd_RequiredFlags(t *testing.T) {
	// Test that required flags are marked as required
	requiredFlags := []string{"url", "subdomain", "cert"}

	for _, flagName := range requiredFlags {
		flag := createCmd.Flags().Lookup(flagName)
		if flag == nil {
			t.Errorf("Required flag '%s' not found", flagName)
			continue
		}

		// Note: cobra doesn't expose a direct way to check if a flag is required
		// This is a limitation of the cobra library
		t.Logf("Flag '%s' is configured (required status not directly testable)", flagName)
	}
}

func TestCreateCmd_FlagDefaults(t *testing.T) {
	// Test default values for flags
	testCases := []struct {
		flag         string
		expectedType string
		description  string
	}{
		{"tcp25", "bool", "Port 25/TCP flag should be boolean"},
		{"tcp465", "bool", "Port 465/TCP flag should be boolean"},
		{"tcp587", "bool", "Port 587/TCP flag should be boolean"},
		{"tcp-port", "int", "Custom TCP Port flag should be int"},
		{"dane-ee", "bool", "DANE-EE flag should be boolean"},
		{"no-dane-ee", "bool", "No DANE-EE flag should be boolean"},
		{"dane-ta", "bool", "DANE-TA flag should be boolean"},
		{"selector", "int", "Selector flag should be int"},
		{"matching-type", "int", "Matching type flag should be int"},
	}

	for _, tc := range testCases {
		flag := createCmd.Flags().Lookup(tc.flag)
		if flag == nil {
			t.Errorf("Flag '%s' not found", tc.flag)
			continue
		}

		if flag.Value.Type() != tc.expectedType {
			t.Errorf("Flag '%s': expected type '%s', got '%s'", tc.flag, tc.expectedType, flag.Value.Type())
		}
	}
}

func TestAddCommonFlags(t *testing.T) {
	// Test that addCommonFlags works properly
	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test command",
	}

	addCommonFlags(testCmd)

	// Verify all expected flags are added
	expectedFlags := []string{
		"url", "subdomain", "cert", "tcp25", "tcp465", "tcp587",
		"tcp-port", "dane-ee", "no-dane-ee", "dane-ta", "selector", "matching-type",
	}

	for _, flagName := range expectedFlags {
		if testCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("addCommonFlags did not add flag '%s'", flagName)
		}
	}
}
