package cloudscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/resourcegraph/armresourcegraph"
)

// AzureClient discovers VMs, storage accounts and SQL databases through
// Azure Resource Graph.
type AzureClient struct {
	cred           *azidentity.ClientSecretCredential
	subscriptionID string
	timeout        time.Duration
}

// NewAzureClient validates the service principal and builds the client.
func NewAzureClient(cred Credentials, timeout time.Duration) (*AzureClient, error) {
	if cred.TenantID == "" || cred.ClientID == "" || cred.ClientSecret == "" {
		return nil, errors.New("azure tenant_id, client_id and client_secret are required")
	}
	token, err := azidentity.NewClientSecretCredential(cred.TenantID, cred.ClientID, cred.ClientSecret, nil)
	if err != nil {
		return nil, fmt.Errorf("azure credential: %w", err)
	}
	if cred.SubscriptionID == "" {
		return nil, errors.New("azure subscription_id is required")
	}
	return &AzureClient{cred: token, subscriptionID: cred.SubscriptionID, timeout: timeout}, nil
}

func (c *AzureClient) Discover(ctx context.Context) ([]Resource, error) {
	client, err := armresourcegraph.NewClient(c.cred, nil)
	if err != nil {
		return nil, err
	}
	query := `resources
| where type in ('microsoft.compute/virtualmachines','microsoft.storage/storageaccounts','microsoft.sql/servers/databases')
| project id, name, type, location, resourceGroup, tags, properties`
	resp, err := client.Resources(ctx, armresourcegraph.QueryRequest{
		Query:         &query,
		Subscriptions: []*string{&c.subscriptionID},
	}, nil)
	if err != nil {
		return nil, err
	}
	rows, columns, err := azureRows(resp.Data)
	if err != nil {
		return nil, err
	}
	idx := func(name string) int {
		for i, col := range columns {
			if strings.EqualFold(col, name) {
				return i
			}
		}
		return -1
	}
	idIdx, nameIdx, typeIdx, locIdx, groupIdx, tagsIdx, propsIdx :=
		idx("id"), idx("name"), idx("type"), idx("location"), idx("resourceGroup"), idx("tags"), idx("properties")

	var out []Resource
	for _, row := range rows {
		id := cellString(row, idIdx)
		typ := strings.ToLower(cellString(row, typeIdx))
		resourceType := azureResourceType(typ)
		if resourceType == "" || id == "" {
			continue
		}
		name := cellString(row, nameIdx)
		if name == "" {
			name = id
		}
		properties := map[string]interface{}{}
		if propsIdx >= 0 && propsIdx < len(row) {
			if raw, ok := row[propsIdx].(map[string]interface{}); ok {
				properties = raw
			}
		}
		status := "active"
		if v, ok := properties["provisioningState"].(string); ok && v != "" {
			status = v
		} else if v, ok := properties["status"].(string); ok && v != "" {
			status = v
		}
		metadata := map[string]interface{}{
			"resource_group": cellString(row, groupIdx),
			"properties":     properties,
		}
		out = append(out, Resource{
			Type: resourceType, ID: id, Name: name, Region: cellString(row, locIdx),
			Status: status, Tags: stringMap(cellMap(row, tagsIdx)), Metadata: metadata,
		})
	}
	return out, nil
}

func azureResourceType(typ string) string {
	switch typ {
	case "microsoft.compute/virtualmachines":
		return "azure_vm"
	case "microsoft.storage/storageaccounts":
		return "azure_storage"
	case "microsoft.sql/servers/databases":
		return "azure_sql"
	default:
		return ""
	}
}

type azureTable struct {
	Columns []struct {
		Name string `json:"name"`
	} `json:"columns"`
	Rows [][]interface{} `json:"rows"`
}

type azureData struct {
	Tables []azureTable `json:"tables"`
}

func azureRows(data any) ([][]interface{}, []string, error) {
	raw, err := json.Marshal(data)
	if err != nil {
		return nil, nil, err
	}
	var d azureData
	if err := json.Unmarshal(raw, &d); err != nil {
		return nil, nil, err
	}
	if len(d.Tables) == 0 {
		return nil, nil, nil
	}
	table := d.Tables[0]
	cols := make([]string, 0, len(table.Columns))
	for _, c := range table.Columns {
		cols = append(cols, c.Name)
	}
	return table.Rows, cols, nil
}

func cellString(row []interface{}, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	if s, ok := row[idx].(string); ok {
		return s
	}
	return ""
}

func cellMap(row []interface{}, idx int) map[string]interface{} {
	if idx < 0 || idx >= len(row) {
		return nil
	}
	if m, ok := row[idx].(map[string]interface{}); ok {
		return m
	}
	return nil
}

func stringMap(in map[string]interface{}) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		if s, ok := v.(string); ok {
			out[k] = s
		}
	}
	return out
}
