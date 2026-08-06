package cloudscan

import (
	"context"
	"fmt"
	"time"
)

// Credentials is the plaintext view of one cloud account credential. It
// exists only in server memory; storage always holds AES-GCM ciphertext.
type Credentials struct {
	Provider        string `json:"provider"`
	AccessKeyID     string `json:"access_key_id,omitempty"`
	SecretAccessKey string `json:"secret_access_key,omitempty"`
	SessionToken    string `json:"session_token,omitempty"`
	TenantID        string `json:"tenant_id,omitempty"`
	ClientID        string `json:"client_id,omitempty"`
	ClientSecret    string `json:"client_secret,omitempty"`
	SubscriptionID  string `json:"subscription_id,omitempty"`
	ProjectID       string `json:"project_id,omitempty"`
	ClientEmail     string `json:"client_email,omitempty"`
	PrivateKey      string `json:"private_key,omitempty"`
}

// Resource is one discovered cloud resource normalized across providers.
type Resource struct {
	Type     string                 `json:"type"`
	ID       string                 `json:"id"`
	Name     string                 `json:"name"`
	Region   string                 `json:"region"`
	Status   string                 `json:"status"`
	Tags     map[string]string      `json:"tags"`
	Metadata map[string]interface{} `json:"metadata"`
}

// Client discovers resources for one cloud account.
type Client interface {
	Discover(ctx context.Context) ([]Resource, error)
}

// NewClient builds the provider client for one account.
func NewClient(cred Credentials, regions []string, timeout time.Duration) (Client, error) {
	switch cred.Provider {
	case "aws":
		return NewAWSClient(cred, regions, timeout)
	case "azure":
		return NewAzureClient(cred, timeout)
	case "gcp":
		return NewGCPClient(cred, timeout)
	default:
		return nil, fmt.Errorf("unsupported cloud provider %q", cred.Provider)
	}
}
