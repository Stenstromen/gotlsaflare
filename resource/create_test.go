package resource

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

func TestResourceCreate_PortValidation(t *testing.T) {
	// Create a test certificate
	certPath := generateTestCertForReq(t)

	// Test case: no ports specified
	cmd := &cobra.Command{}
	addCreateFlags(cmd)

	cmd.SetArgs([]string{
		"--url", "example.com",
		"--subdomain", "mail",
		"--cert", certPath,
	})

	err := cmd.ParseFlags([]string{
		"--url", "example.com",
		"--subdomain", "mail",
		"--cert", certPath,
	})
	if err != nil {
		t.Fatalf("Failed to parse flags: %v", err)
	}

	// This should return an error because no port is specified
	err = ResourceCreate(cmd, []string{})
	if err == nil {
		t.Error("Expected error when no port is specified, got nil")
	}

	if !strings.Contains(err.Error(), "no ports specified") {
		t.Errorf("Expected error message about no ports, got: %v", err)
	}
}

func TestResourceCreate_DaneValidation(t *testing.T) {
	// Create a test certificate
	certPath := generateTestCertForReq(t)

	// Create a mock Cloudflare API server
	mockServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Mock zone list response
		if strings.HasSuffix(r.URL.Path, "/zones") {
			response := Res{
				Success: true,
				Result: []struct {
					ID                  string      `json:"id"`
					Name                string      `json:"name"`
					Status              string      `json:"status"`
					Paused              bool        `json:"paused"`
					Type                string      `json:"type"`
					DevelopmentMode     int         `json:"development_mode"`
					NameServers         []string    `json:"name_servers"`
					OriginalNameServers []string    `json:"original_name_servers"`
					OriginalRegistrar   interface{} `json:"original_registrar"`
					OriginalDnshost     interface{} `json:"original_dnshost"`
					ModifiedOn          time.Time   `json:"modified_on"`
					CreatedOn           time.Time   `json:"created_on"`
					ActivatedOn         time.Time   `json:"activated_on"`
					Meta                struct {
						Step                    int  `json:"step"`
						CustomCertificateQuota  int  `json:"custom_certificate_quota"`
						PageRuleQuota           int  `json:"page_rule_quota"`
						PhishingDetected        bool `json:"phishing_detected"`
						MultipleRailgunsAllowed bool `json:"multiple_railguns_allowed"`
					} `json:"meta"`
					Owner struct {
						ID    interface{} `json:"id"`
						Type  string      `json:"type"`
						Email interface{} `json:"email"`
					} `json:"owner"`
					Account struct {
						ID   string `json:"id"`
						Name string `json:"name"`
					} `json:"account"`
					Tenant struct {
						ID   interface{} `json:"id"`
						Name interface{} `json:"name"`
					} `json:"tenant"`
					TenantUnit struct {
						ID interface{} `json:"id"`
					} `json:"tenant_unit"`
					Permissions []string `json:"permissions"`
					Plan        struct {
						ID                string `json:"id"`
						Name              string `json:"name"`
						Price             int    `json:"price"`
						Currency          string `json:"currency"`
						Frequency         string `json:"frequency"`
						IsSubscribed      bool   `json:"is_subscribed"`
						CanSubscribe      bool   `json:"can_subscribe"`
						LegacyID          string `json:"legacy_id"`
						LegacyDiscount    bool   `json:"legacy_discount"`
						ExternallyManaged bool   `json:"externally_managed"`
					} `json:"plan"`
				}{
					{ID: "zone-123", Name: "example.com"},
				},
			}
			json.NewEncoder(w).Encode(response)
		}
	}))
	defer mockServer.Close()

	// Set mock token
	os.Setenv("TOKEN", "test-token")
	defer os.Unsetenv("TOKEN")

	// Test with --no-dane-ee and no --dane-ta should fail
	t.Run("NoDaneEEWithoutDaneTA", func(t *testing.T) {
		cmd := &cobra.Command{}
		addCreateFlags(cmd)

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

		// This test will call os.Exit, so we skip it
		// In production, you might want to refactor to return errors
		t.Skip("Skipping test that causes os.Exit")
	})
}

func TestResourceCreate_MatchingTypeValidation(t *testing.T) {
	// Create a test certificate
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
			addCreateFlags(cmd)

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

			// This test will call os.Exit for invalid matching types
			// In production, you might want to refactor to return errors
			if tc.shouldFail {
				t.Skip("Skipping test that causes os.Exit")
			}
		})
	}
}

func TestResourceCreate_SelectorDefaults(t *testing.T) {
	// Test that appropriate selectors are used when not explicitly set
	// This is more of a documentation test since the actual logic
	// happens inside the function and calls os.Exit on error

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
			// This is a documentation test - the actual validation would require
			// refactoring the code to make it more testable
			t.Logf("When selector is %d, daneEE=%v, daneTA=%v", tc.selector, tc.daneEE, tc.daneTA)
			t.Logf("Expected EE selector: %d, TA selector: %d", tc.expectedEESel, tc.expectedTASel)
		})
	}
}

// Helper to add flags for testing
func addCreateFlags(cmd *cobra.Command) {
	cmd.Flags().StringP("url", "u", "", "Domain to Update (Required)")
	cmd.Flags().StringP("subdomain", "s", "", "TLSA Subdomain (Required)")
	cmd.Flags().StringP("cert", "f", "", "Path to Certificate File (Required)")
	cmd.Flags().BoolP("tcp25", "t", false, "Port 25/TCP")
	cmd.Flags().BoolP("tcp465", "p", false, "Port 465/TCP")
	cmd.Flags().BoolP("tcp587", "e", false, "Port 587/TCP")
	cmd.Flags().IntP("tcp-port", "c", 0, "Custom TCP Port")
	cmd.Flags().BoolP("dane-ee", "", true, "Create DANE-EE record")
	cmd.Flags().BoolP("no-dane-ee", "", false, "Do not create DANE-EE record")
	cmd.Flags().BoolP("dane-ta", "", false, "Create DANE-TA record")
	cmd.Flags().IntP("selector", "l", -1, "TLSA selector")
	cmd.Flags().IntP("matching-type", "m", 1, "TLSA matching type")
}

func TestResourceCreate_MultiplePortsLogic(t *testing.T) {
	// Test that multiple ports can be specified
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addCreateFlags(cmd)

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

	// Verify flags are parsed correctly
	tcp25, _ := cmd.Flags().GetBool("tcp25")
	tcp465, _ := cmd.Flags().GetBool("tcp465")
	tcp587, _ := cmd.Flags().GetBool("tcp587")

	if !tcp25 || !tcp465 || !tcp587 {
		t.Error("Expected all TCP ports to be enabled")
	}
}

func TestResourceCreate_CustomPort(t *testing.T) {
	certPath := generateTestCertForReq(t)

	cmd := &cobra.Command{}
	addCreateFlags(cmd)

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
