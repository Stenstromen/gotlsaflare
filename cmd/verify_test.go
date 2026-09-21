package cmd

import "testing"

func TestVerifyCmd_Structure(t *testing.T) {
	if verifyCmd == nil {
		t.Fatal("verifyCmd should not be nil")
	}
	if verifyCmd.Use != "verify" {
		t.Errorf("Expected Use 'verify', got '%s'", verifyCmd.Use)
	}
	if verifyCmd.Short != "Verify TLSA DNS records against a certificate" {
		t.Errorf("Expected Short description, got '%s'", verifyCmd.Short)
	}
	if verifyCmd.RunE == nil {
		t.Error("Expected RunE to be set")
	}
}

func TestVerifyCmd_Flags(t *testing.T) {
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
		"starttls",
	}

	for _, flagName := range expectedFlags {
		if verifyCmd.Flags().Lookup(flagName) == nil {
			t.Errorf("Expected flag '%s' to exist", flagName)
		}
	}

	cert := verifyCmd.Flags().Lookup("cert")
	if cert.DefValue != "" {
		t.Errorf("cert should default to empty so the endpoint is used, got %q", cert.DefValue)
	}
	starttls := verifyCmd.Flags().Lookup("starttls")
	if starttls.DefValue != "auto" {
		t.Errorf("starttls should default to auto, got %q", starttls.DefValue)
	}
}

func TestVerifyCmd_Registered(t *testing.T) {
	for _, command := range rootCmd.Commands() {
		if command.Name() == "verify" {
			return
		}
	}
	t.Fatal("verify command is not registered")
}
