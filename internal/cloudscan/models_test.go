package cloudscan

import (
	"strings"
	"testing"
	"time"
)

func TestAzureRowsParsing(t *testing.T) {
	data := map[string]interface{}{
		"tables": []interface{}{
			map[string]interface{}{
				"columns": []interface{}{
					map[string]interface{}{"name": "id"},
					map[string]interface{}{"name": "name"},
					map[string]interface{}{"name": "type"},
					map[string]interface{}{"name": "location"},
				},
				"rows": []interface{}{
					[]interface{}{"/subscriptions/s1/resourceGroups/rg/providers/Microsoft.Compute/virtualMachines/vm1", "vm1", "microsoft.compute/virtualmachines", "eastus"},
				},
			},
		},
	}
	rows, cols, err := azureRows(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(cols) != 4 || cols[0] != "id" {
		t.Fatalf("unexpected parse: rows=%v cols=%v", rows, cols)
	}
	if azureResourceType("microsoft.compute/virtualmachines") != "azure_vm" ||
		azureResourceType("microsoft.storage/storageaccounts") != "azure_storage" ||
		azureResourceType("microsoft.sql/servers/databases") != "azure_sql" ||
		azureResourceType("other") != "" {
		t.Fatal("resource type mapping wrong")
	}
}

func TestNewClientValidation(t *testing.T) {
	if _, err := NewClient(Credentials{Provider: "aws"}, nil, time.Second); err == nil {
		t.Fatal("aws without keys must fail")
	}
	if _, err := NewClient(Credentials{Provider: "azure"}, nil, time.Second); err == nil {
		t.Fatal("azure without tenant/client must fail")
	}
	if _, err := NewClient(Credentials{Provider: "gcp"}, nil, time.Second); err == nil {
		t.Fatal("gcp without service account must fail")
	}
	if _, err := NewClient(Credentials{Provider: "oracle"}, nil, time.Second); err == nil ||
		!strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("unknown provider error = %v", err)
	}
}

func TestZoneToRegion(t *testing.T) {
	if got := zoneToRegion("us-central1-a"); got != "us-central1" {
		t.Fatalf("zoneToRegion = %q", got)
	}
	if got := lastPathSegment("projects/p/zones/us-central1-a"); got != "us-central1-a" {
		t.Fatalf("lastPathSegment = %q", got)
	}
}
