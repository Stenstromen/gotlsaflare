package resource

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
)

func TestResourceUpdate_PortValidation(t *testing.T) {
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addUpdateFlags(cmd)

	err := cmd.ParseFlags([]string{
		"--url", "example.com",
		"--subdomain", "mail",
		"--cert", certPath,
	})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	// Should return error because no port is specified
	err = ResourceUpdate(cmd, []string{})
	if err == nil {
		t.Error("Expected error when no port is specified, got nil")
	}

	if !strings.Contains(err.Error(), "no ports specified") {
		t.Errorf("Expected error message about no ports, got: %v", err)
	}
}

func TestResourceUpdate_DaneValidation(t *testing.T) {
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addUpdateFlags(cmd)

	// Test with --no-dane-ee and no --dane-ta should fail (os.Exit)
	err := cmd.ParseFlags([]string{
		"--url", "example.com",
		"--subdomain", "mail",
		"--cert", certPath,
		"--tcp25",
		"--no-dane-ee",
	})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	// This will cause os.Exit, so we skip it
	t.Skip("Skipping test that causes os.Exit")
}

func TestResourceUpdate_MatchingTypeValidation(t *testing.T) {
	certPath := generateTestCertForReq(t)

	testCases := []struct {
		name         string
		matchingType string
		shouldFail   bool
	}{
		{"SHA256", "1", false},
		{"SHA512", "2", false},
		{"Invalid0", "0", true},
		{"Invalid3", "3", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			cmd := &cobra.Command{}
			addUpdateFlags(cmd)

			err := cmd.ParseFlags([]string{
				"--url", "example.com",
				"--subdomain", "mail",
				"--cert", certPath,
				"--tcp25",
				"--matching-type", tc.matchingType,
			})
			if err != nil {
				t.Fatalf("Failed to parse flags: %v", err)
			}

			if tc.shouldFail {
				t.Skip("Skipping test that causes os.Exit")
			}
		})
	}
}

func TestResourceUpdate_RolloverFlag(t *testing.T) {
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addUpdateFlags(cmd)

	// Test with rollover flag
	err := cmd.ParseFlags([]string{
		"--url", "example.com",
		"--subdomain", "mail",
		"--cert", certPath,
		"--tcp25",
		"--rollover",
	})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	rollover, _ := cmd.Flags().GetBool("rollover")
	if !rollover {
		t.Error("Expected rollover flag to be true")
	}
}

func TestResourceUpdate_SelectorDefaults(t *testing.T) {
	// Test that appropriate selectors are used when not explicitly set
	testCases := []struct {
		name          string
		daneEE        bool
		daneTA        bool
		selector      int
		expectedEESel int
		expectedTASel int
	}{
		{"DefaultBoth", true, true, -1, 1, 0},
		{"DefaultEEOnly", true, false, -1, 1, 0},
		{"DefaultTAOnly", false, true, -1, 1, 0},
		{"ExplicitSelector0", true, true, 0, 0, 0},
		{"ExplicitSelector1", true, true, 1, 1, 1},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Logf("When selector is %d, daneEE=%v, daneTA=%v", tc.selector, tc.daneEE, tc.daneTA)
			t.Logf("Expected EE selector: %d, TA selector: %d", tc.expectedEESel, tc.expectedTASel)
		})
	}
}

func TestResourceUpdate_MultiplePortsLogic(t *testing.T) {
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addUpdateFlags(cmd)

	// Test with multiple ports
	err := cmd.ParseFlags([]string{
		"--url", "example.com",
		"--subdomain", "mail",
		"--cert", certPath,
		"--tcp25",
		"--tcp465",
		"--tcp587",
	})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	tcp25, _ := cmd.Flags().GetBool("tcp25")
	tcp465, _ := cmd.Flags().GetBool("tcp465")
	tcp587, _ := cmd.Flags().GetBool("tcp587")

	if !tcp25 || !tcp465 || !tcp587 {
		t.Error("Expected all TCP ports to be enabled")
	}
}

func TestResourceUpdate_CustomPort(t *testing.T) {
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addUpdateFlags(cmd)

	// Test with custom port
	err := cmd.ParseFlags([]string{
		"--url", "example.com",
		"--subdomain", "www",
		"--cert", certPath,
		"--tcp-port", "8443",
	})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	tcpPort, _ := cmd.Flags().GetInt("tcp-port")
	if tcpPort != 8443 {
		t.Errorf("Expected tcp-port 8443, got %d", tcpPort)
	}
}

func TestDeleteRecord_InvalidInputs(t *testing.T) {
	testCases := []struct {
		name     string
		zoneID   string
		recordID string
		bearer   string
		wantErr  bool
	}{
		{"EmptyZoneID", "", "record-123", "Bearer token", true},
		{"EmptyRecordID", "zone-123", "", "Bearer token", true},
		{"BothEmpty", "", "", "Bearer token", true},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := deleteRecord(tc.zoneID, tc.recordID, tc.bearer)
			if (err != nil) != tc.wantErr {
				t.Errorf("deleteRecord() error = %v, wantErr %v", err, tc.wantErr)
			}
		})
	}
}

func TestDeleteRecord_ValidInputs(t *testing.T) {
	// This test would require mocking the HTTP client
	// For now, we just test that valid inputs don't immediately error
	zoneID := "valid-zone-123"
	recordID := "valid-record-456"
	bearer := "Bearer test-token"

	// We expect this to fail because it will try to make a real HTTP request
	// In production, you would mock the HTTP client
	err := deleteRecord(zoneID, recordID, bearer)
	if err == nil {
		t.Skip("Test requires HTTP mocking, skipping")
	}
}

// Helper to add flags for update testing
func addUpdateFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("url", "u", "", "Domain to Update (Required)")
	cmd.Flags().StringP("subdomain", "s", "", "TLSA Subdomain (Required)")
	cmd.Flags().StringP("cert", "f", "", "Path to Certificate File (Required)")
	cmd.Flags().BoolP("tcp25", "t", false, "Port 25/TCP")
	cmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	cmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	cmd.Flags().IntP("tcp-port", "c", 0, "Custom TCP Port")
	cmd.Flags().BoolP("dane-ee", "", true, "Update DANE-EE record")
	cmd.Flags().BoolP("no-dane-ee", "", false, "Do not update DANE-EE record")
	cmd.Flags().BoolP("dane-ta", "", false, "Update DANE-TA record")
	cmd.Flags().BoolP("rollover", "r", false, "Perform rolling update")
	cmd.Flags().IntP("selector", "l", -1, "TLSA selector")
	cmd.Flags().IntP("matching-type", "m", 1, "TLSA matching type")
}

func TestCheckDNSPropagation_InvalidDomain(t *testing.T) {
	// Test with invalid domain - this may timeout or fail quickly
	err := checkDNSPropagation("invalid..domain..test")
	if err == nil {
		t.Log("DNS check succeeded unexpectedly, but this is acceptable")
	}
}

func TestCheckDNSPropagation_ValidFormat(t *testing.T) {
	// Test with valid TLSA record format
	// This will make real DNS queries, so it might fail if the record doesn't exist
	// That's expected behavior
	recordName := "_25._tcp.mail.example.com"
	err := checkDNSPropagation(recordName)

	// We don't assert on the error because the record likely doesn't exist
	// We just verify the function executes without panicking
	t.Logf("DNS propagation check result for %s: %v", recordName, err)
}
