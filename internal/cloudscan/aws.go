package cloudscan

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	ec2types "github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"github.com/aws/aws-sdk-go-v2/service/rds"
	rdstypes "github.com/aws/aws-sdk-go-v2/service/rds/types"
	"github.com/aws/aws-sdk-go-v2/service/s3"
)

// AWSClient discovers EC2 instances, S3 buckets and RDS instances.
type AWSClient struct {
	cfg     aws.Config
	regions []string
	timeout time.Duration
}

// NewAWSClient validates static access keys and builds the client.
func NewAWSClient(cred Credentials, regions []string, timeout time.Duration) (*AWSClient, error) {
	if cred.AccessKeyID == "" || cred.SecretAccessKey == "" {
		return nil, errors.New("aws access_key_id and secret_access_key are required")
	}
	cfg := aws.Config{
		Region:      "us-east-1",
		Credentials: credentials.NewStaticCredentialsProvider(cred.AccessKeyID, cred.SecretAccessKey, cred.SessionToken),
	}
	return &AWSClient{cfg: cfg, regions: regions, timeout: timeout}, nil
}

func (c *AWSClient) Discover(ctx context.Context) ([]Resource, error) {
	regions := c.regions
	if len(regions) == 0 {
		discovered, err := c.enabledRegions(ctx)
		if err != nil {
			return nil, fmt.Errorf("enumerate aws regions: %w", err)
		}
		regions = discovered
	}
	var out []Resource
	for _, region := range regions {
		instances, err := c.listInstances(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("list ec2 instances in %s: %w", region, err)
		}
		out = append(out, instances...)
		databases, err := c.listRDSInstances(ctx, region)
		if err != nil {
			return nil, fmt.Errorf("list rds instances in %s: %w", region, err)
		}
		out = append(out, databases...)
	}
	buckets, err := c.listBuckets(ctx)
	if err != nil {
		return nil, fmt.Errorf("list s3 buckets: %w", err)
	}
	out = append(out, buckets...)
	return out, nil
}

func (c *AWSClient) enabledRegions(ctx context.Context) ([]string, error) {
	client := ec2.NewFromConfig(c.cfg)
	out, err := client.DescribeRegions(ctx, &ec2.DescribeRegionsInput{})
	if err != nil {
		return nil, err
	}
	var regions []string
	for _, r := range out.Regions {
		if r.RegionName != nil {
			regions = append(regions, *r.RegionName)
		}
	}
	if len(regions) == 0 {
		regions = []string{"us-east-1"}
	}
	return regions, nil
}

func (c *AWSClient) listInstances(ctx context.Context, region string) ([]Resource, error) {
	regionCfg := c.cfg
	regionCfg.Region = region
	client := ec2.NewFromConfig(regionCfg)
	paginator := ec2.NewDescribeInstancesPaginator(client, &ec2.DescribeInstancesInput{})
	var out []Resource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, reservation := range page.Reservations {
			for _, inst := range reservation.Instances {
				if inst.InstanceId == nil {
					continue
				}
				tags := awsTags(inst.Tags)
				name := tags["Name"]
				if name == "" {
					name = *inst.InstanceId
				}
				status := ""
				if inst.State != nil {
					status = string(inst.State.Name)
				}
				metadata := map[string]interface{}{
					"instance_type": string(inst.InstanceType),
					"vpc_id":        derefString(inst.VpcId),
					"subnet_id":     derefString(inst.SubnetId),
					"public_ip":     derefString(inst.PublicIpAddress),
					"private_ip":    derefString(inst.PrivateIpAddress),
					"platform":      string(inst.Platform),
					"launch_time":   inst.LaunchTime,
				}
				out = append(out, Resource{
					Type: "ec2_instance", ID: *inst.InstanceId, Name: name,
					Region: region, Status: status, Tags: tags, Metadata: metadata,
				})
			}
		}
	}
	return out, nil
}

func (c *AWSClient) listBuckets(ctx context.Context) ([]Resource, error) {
	client := s3.NewFromConfig(c.cfg)
	out, err := client.ListBuckets(ctx, &s3.ListBucketsInput{})
	if err != nil {
		return nil, err
	}
	var resources []Resource
	for _, bucket := range out.Buckets {
		if bucket.Name == nil {
			continue
		}
		region := "us-east-1"
		if loc, err := client.GetBucketLocation(ctx, &s3.GetBucketLocationInput{Bucket: bucket.Name}); err == nil {
			if loc.LocationConstraint != "" {
				region = string(loc.LocationConstraint)
			}
			if region == "" {
				region = "us-east-1"
			}
		}
		tags := map[string]string{}
		if tg, err := client.GetBucketTagging(ctx, &s3.GetBucketTaggingInput{Bucket: bucket.Name}); err == nil {
			for _, t := range tg.TagSet {
				if t.Key != nil && t.Value != nil {
					tags[*t.Key] = *t.Value
				}
			}
		}
		resources = append(resources, Resource{
			Type: "s3_bucket", ID: *bucket.Name, Name: *bucket.Name,
			Region: region, Status: "active", Tags: tags,
			Metadata: map[string]interface{}{"creation_date": bucket.CreationDate},
		})
	}
	return resources, nil
}

func (c *AWSClient) listRDSInstances(ctx context.Context, region string) ([]Resource, error) {
	regionCfg := c.cfg
	regionCfg.Region = region
	client := rds.NewFromConfig(regionCfg)
	paginator := rds.NewDescribeDBInstancesPaginator(client, &rds.DescribeDBInstancesInput{})
	var out []Resource
	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		for _, db := range page.DBInstances {
			if db.DBInstanceIdentifier == nil {
				continue
			}
			tags := map[string]string{}
			if db.DBInstanceArn != nil {
				if tg, err := client.ListTagsForResource(ctx, &rds.ListTagsForResourceInput{ResourceName: db.DBInstanceArn}); err == nil {
					for _, t := range tg.TagList {
						if t.Key != nil && t.Value != nil {
							tags[*t.Key] = *t.Value
						}
					}
				}
			}
			metadata := map[string]interface{}{
				"engine":         derefString(db.Engine),
				"engine_version": derefString(db.EngineVersion),
				"instance_class": derefString(db.DBInstanceClass),
				"endpoint":       rdsEndpoint(db.Endpoint),
				"arn":            derefString(db.DBInstanceArn),
			}
			out = append(out, Resource{
				Type: "rds_instance", ID: *db.DBInstanceIdentifier,
				Name: *db.DBInstanceIdentifier, Region: region,
				Status: derefString(db.DBInstanceStatus), Tags: tags, Metadata: metadata,
			})
		}
	}
	return out, nil
}

func awsTags(tags []ec2types.Tag) map[string]string {
	out := map[string]string{}
	for _, t := range tags {
		if t.Key != nil && t.Value != nil {
			out[*t.Key] = *t.Value
		}
	}
	return out
}

func rdsEndpoint(ep *rdstypes.Endpoint) string {
	if ep == nil || ep.Address == nil {
		return ""
	}
	return *ep.Address
}

func derefString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}
