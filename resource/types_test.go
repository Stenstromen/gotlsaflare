package resource

import (
	"encoding/json"
	"testing"
	"time"
)

func TestJSONRequest_Serialization(t *testing.T) {
	data := Data{
		Usage:        3,
		Selector:     1,
		Matchingtype: 1,
		Certificate:  "abcdef1234567890",
	}

	req := JSONRequest{
		Type:     "TLSA",
		Name:     "_25._tcp.mail",
		Data:     data,
		Ttl:      3600,
		Priority: 10,
		Proxied:  false,
		Comment:  "Test comment",
	}

	// Test marshaling
	jsonBytes, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("Failed to marshal JSONRequest: %v", err)
	}

	// Test unmarshaling
	var decoded JSONRequest
	if err := json.Unmarshal(jsonBytes, &decoded); err != nil {
		t.Fatalf("Failed to unmarshal JSONRequest: %v", err)
	}

	// Verify all fields
	if decoded.Type != req.Type {
		t.Errorf("Type mismatch: expected %s, got %s", req.Type, decoded.Type)
	}
	if decoded.Name != req.Name {
		t.Errorf("Name mismatch: expected %s, got %s", req.Name, decoded.Name)
	}
	if decoded.Ttl != req.Ttl {
		t.Errorf("Ttl mismatch: expected %d, got %d", req.Ttl, decoded.Ttl)
	}
	if decoded.Priority != req.Priority {
		t.Errorf("Priority mismatch: expected %d, got %d", req.Priority, decoded.Priority)
	}
	if decoded.Proxied != req.Proxied {
		t.Errorf("Proxied mismatch: expected %v, got %v", req.Proxied, decoded.Proxied)
	}
	if decoded.Comment != req.Comment {
		t.Errorf("Comment mismatch: expected %s, got %s", req.Comment, decoded.Comment)
	}
	if decoded.Data.Usage != req.Data.Usage {
		t.Errorf("Data.Usage mismatch: expected %d, got %d", req.Data.Usage, decoded.Data.Usage)
	}
	if decoded.Data.Selector != req.Data.Selector {
		t.Errorf("Data.Selector mismatch: expected %d, got %d", req.Data.Selector, decoded.Data.Selector)
	}
	if decoded.Data.Matchingtype != req.Data.Matchingtype {
		t.Errorf("Data.Matchingtype mismatch: expected %d, got %d", req.Data.Matchingtype, decoded.Data.Matchingtype)
	}
	if decoded.Data.Certificate != req.Data.Certificate {
		t.Errorf("Data.Certificate mismatch: expected %s, got %s", req.Data.Certificate, decoded.Data.Certificate)
	}
}

func TestData_JSONTags(t *testing.T) {
	data := Data{
		Usage:        3,
		Selector:     1,
		Matchingtype: 2,
		Certificate:  "test123",
	}

	jsonBytes, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("Failed to marshal Data: %v", err)
	}

	jsonString := string(jsonBytes)

	// Verify JSON field names match the expected format
	expectedFields := []string{
		`"usage":3`,
		`"selector":1`,
		`"matching_type":2`,
		`"certificate":"test123"`,
	}

	for _, field := range expectedFields {
		if !contains(jsonString, field) {
			t.Errorf("Expected JSON to contain %s, got: %s", field, jsonString)
		}
	}
}

func TestRecordsRes_Deserialization(t *testing.T) {
	jsonData := `{
		"result": [{
			"id": "test-id-123",
			"zone_id": "zone-456",
			"zone_name": "example.com",
			"name": "_25._tcp.mail.example.com",
			"type": "TLSA",
			"content": "",
			"proxiable": false,
			"proxied": false,
			"ttl": 3600,
			"locked": false,
			"data": {
				"certificate": "abc123",
				"matching_type": 1,
				"selector": 1,
				"usage": 3
			},
			"meta": {
				"auto_added": false,
				"managed_by_apps": false,
				"managed_by_argo_tunnel": false,
				"source": "primary"
			},
			"comment": "Test comment",
			"tags": [],
			"created_on": "2023-01-01T00:00:00Z",
			"modified_on": "2023-01-01T00:00:00Z"
		}],
		"success": true,
		"errors": [],
		"messages": [],
		"result_info": {
			"page": 1,
			"per_page": 20,
			"count": 1,
			"total_count": 1,
			"total_pages": 1
		}
	}`

	var recordsRes RecordsRes
	if err := json.Unmarshal([]byte(jsonData), &recordsRes); err != nil {
		t.Fatalf("Failed to unmarshal RecordsRes: %v", err)
	}

	if !recordsRes.Success {
		t.Error("Expected Success to be true")
	}

	if len(recordsRes.Result) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(recordsRes.Result))
	}

	record := recordsRes.Result[0]

	if record.ID != "test-id-123" {
		t.Errorf("Expected ID 'test-id-123', got '%s'", record.ID)
	}

	if record.Type != "TLSA" {
		t.Errorf("Expected Type 'TLSA', got '%s'", record.Type)
	}

	if record.Data.Usage != 3 {
		t.Errorf("Expected Usage 3, got %d", record.Data.Usage)
	}

	if record.Data.Selector != 1 {
		t.Errorf("Expected Selector 1, got %d", record.Data.Selector)
	}

	if record.Data.MatchingType != 1 {
		t.Errorf("Expected MatchingType 1, got %d", record.Data.MatchingType)
	}

	if record.Data.Certificate != "abc123" {
		t.Errorf("Expected Certificate 'abc123', got '%s'", record.Data.Certificate)
	}
}

func TestRes_Deserialization(t *testing.T) {
	jsonData := `{
		"result": [{
			"id": "zone-123",
			"name": "example.com",
			"status": "active",
			"paused": false,
			"type": "full",
			"development_mode": 0,
			"name_servers": ["ns1.cloudflare.com", "ns2.cloudflare.com"],
			"original_name_servers": ["ns1.example.com"],
			"original_registrar": null,
			"original_dnshost": null,
			"modified_on": "2023-01-01T00:00:00Z",
			"created_on": "2023-01-01T00:00:00Z",
			"activated_on": "2023-01-01T00:00:00Z",
			"meta": {
				"step": 4,
				"custom_certificate_quota": 0,
				"page_rule_quota": 3,
				"phishing_detected": false,
				"multiple_railguns_allowed": false
			},
			"owner": {
				"id": null,
				"type": "user",
				"email": null
			},
			"account": {
				"id": "account-456",
				"name": "Test Account"
			},
			"tenant": {
				"id": null,
				"name": null
			},
			"tenant_unit": {
				"id": null
			},
			"permissions": ["#zone:read"],
			"plan": {
				"id": "plan-789",
				"name": "Free",
				"price": 0,
				"currency": "USD",
				"frequency": "monthly",
				"is_subscribed": true,
				"can_subscribe": false,
				"legacy_id": "free",
				"legacy_discount": false,
				"externally_managed": false
			}
		}],
		"result_info": {
			"page": 1,
			"per_page": 20,
			"total_pages": 1,
			"count": 1,
			"total_count": 1
		},
		"success": true,
		"errors": [],
		"messages": []
	}`

	var res Res
	if err := json.Unmarshal([]byte(jsonData), &res); err != nil {
		t.Fatalf("Failed to unmarshal Res: %v", err)
	}

	if !res.Success {
		t.Error("Expected Success to be true")
	}

	if len(res.Result) != 1 {
		t.Fatalf("Expected 1 result, got %d", len(res.Result))
	}

	zone := res.Result[0]

	if zone.ID != "zone-123" {
		t.Errorf("Expected ID 'zone-123', got '%s'", zone.ID)
	}

	if zone.Name != "example.com" {
		t.Errorf("Expected Name 'example.com', got '%s'", zone.Name)
	}

	if zone.Status != "active" {
		t.Errorf("Expected Status 'active', got '%s'", zone.Status)
	}
}

func TestDNSRecord_Type(t *testing.T) {
	// Test that DNSRecord can be created and used
	record := DNSRecord{
		ID:       "test-123",
		ZoneID:   "zone-456",
		ZoneName: "example.com",
		Name:     "_25._tcp.mail.example.com",
		Type:     "TLSA",
		Content:  "",
		TTL:      3600,
		Data: struct {
			Certificate  string `json:"certificate"`
			MatchingType int    `json:"matching_type"`
			Selector     int    `json:"selector"`
			Usage        int    `json:"usage"`
		}{
			Certificate:  "abc123",
			MatchingType: 1,
			Selector:     1,
			Usage:        3,
		},
		CreatedOn:  time.Now(),
		ModifiedOn: time.Now(),
	}

	if record.ID != "test-123" {
		t.Errorf("Expected ID 'test-123', got '%s'", record.ID)
	}

	if record.Type != "TLSA" {
		t.Errorf("Expected Type 'TLSA', got '%s'", record.Type)
	}

	if record.Data.Usage != 3 {
		t.Errorf("Expected Usage 3, got %d", record.Data.Usage)
	}
}

// Helper function for string contains check
func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 ||
		(len(s) > 0 && (s[0:len(substr)] == substr || contains(s[1:], substr))))
}
