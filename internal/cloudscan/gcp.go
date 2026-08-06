package cloudscan

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	compute "google.golang.org/api/compute/v1"
	"google.golang.org/api/option"
	sqladmin "google.golang.org/api/sqladmin/v1"
	storage "google.golang.org/api/storage/v1"
)

// GCPClient discovers Compute instances, GCS buckets and Cloud SQL
// instances with a service account.
type GCPClient struct {
	projectID string
	credJSON  []byte
	timeout   time.Duration
}

// NewGCPClient validates the service account fields and builds the client.
func NewGCPClient(cred Credentials, timeout time.Duration) (*GCPClient, error) {
	if cred.ProjectID == "" || cred.ClientEmail == "" || cred.PrivateKey == "" {
		return nil, errors.New("gcp project_id, client_email and private_key are required")
	}
	sa := map[string]string{
		"type":         "service_account",
		"project_id":   cred.ProjectID,
		"client_email": cred.ClientEmail,
		"private_key":  cred.PrivateKey,
	}
	raw, err := json.Marshal(sa)
	if err != nil {
		return nil, err
	}
	return &GCPClient{projectID: cred.ProjectID, credJSON: raw, timeout: timeout}, nil
}

func (c *GCPClient) Discover(ctx context.Context) ([]Resource, error) {
	opts := []option.ClientOption{option.WithCredentialsJSON(c.credJSON)}
	computeSvc, err := compute.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp compute client: %w", err)
	}
	storageSvc, err := storage.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp storage client: %w", err)
	}
	sqlSvc, err := sqladmin.NewService(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("gcp sql client: %w", err)
	}

	var out []Resource
	instances, err := c.listInstances(ctx, computeSvc)
	if err != nil {
		return nil, err
	}
	out = append(out, instances...)
	buckets, err := c.listBuckets(ctx, storageSvc)
	if err != nil {
		return nil, err
	}
	out = append(out, buckets...)
	sqls, err := c.listSQL(ctx, sqlSvc)
	if err != nil {
		return nil, err
	}
	out = append(out, sqls...)
	return out, nil
}

func (c *GCPClient) listInstances(ctx context.Context, svc *compute.Service) ([]Resource, error) {
	agg, err := svc.Instances.AggregatedList(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp list instances: %w", err)
	}
	var out []Resource
	for _, scoped := range agg.Items {
		for _, inst := range scoped.Instances {
			if inst == nil || inst.Name == "" {
				continue
			}
			zone := lastPathSegment(inst.Zone)
			region := zoneToRegion(zone)
			metadata := map[string]interface{}{
				"zone":               zone,
				"machine_type":       lastPathSegment(inst.MachineType),
				"status":             inst.Status,
				"network_interfaces": inst.NetworkInterfaces,
			}
			out = append(out, Resource{
				Type: "gcp_instance", ID: inst.Name, Name: inst.Name,
				Region: region, Status: inst.Status, Tags: copyStringMap(inst.Labels),
				Metadata: metadata,
			})
		}
	}
	return out, nil
}

func (c *GCPClient) listBuckets(ctx context.Context, svc *storage.Service) ([]Resource, error) {
	resp, err := svc.Buckets.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp list buckets: %w", err)
	}
	var out []Resource
	for _, b := range resp.Items {
		if b == nil || b.Name == "" {
			continue
		}
		out = append(out, Resource{
			Type: "gcp_bucket", ID: b.Name, Name: b.Name,
			Region: b.Location, Status: "active", Tags: copyStringMap(b.Labels),
			Metadata: map[string]interface{}{
				"storage_class": b.StorageClass,
				"created_at":    b.TimeCreated,
			},
		})
	}
	return out, nil
}

func (c *GCPClient) listSQL(ctx context.Context, svc *sqladmin.Service) ([]Resource, error) {
	resp, err := svc.Instances.List(c.projectID).Context(ctx).Do()
	if err != nil {
		return nil, fmt.Errorf("gcp list sql instances: %w", err)
	}
	var out []Resource
	for _, inst := range resp.Items {
		if inst == nil || inst.Name == "" {
			continue
		}
		metadata := map[string]interface{}{
			"database_version": inst.DatabaseVersion,
			"state":            inst.State,
		}
		if inst.Settings != nil {
			metadata["tier"] = inst.Settings.Tier
		}
		out = append(out, Resource{
			Type: "gcp_sql", ID: inst.Name, Name: inst.Name,
			Region: inst.Region, Status: inst.State,
			Tags:     copyStringMap(sqlLabels(inst.Settings)),
			Metadata: metadata,
		})
	}
	return out, nil
}

func sqlLabels(s *sqladmin.Settings) map[string]string {
	if s == nil {
		return nil
	}
	return s.UserLabels
}

func copyStringMap(in map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range in {
		out[k] = v
	}
	return out
}

func lastPathSegment(s string) string {
	if i := strings.LastIndex(s, "/"); i >= 0 {
		return s[i+1:]
	}
	return s
}

func zoneToRegion(zone string) string {
	parts := strings.Split(zone, "-")
	if len(parts) >= 3 {
		return strings.Join(parts[:len(parts)-1], "-")
	}
	return zone
}
