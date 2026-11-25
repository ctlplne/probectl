// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package flow

import (
	"errors"
	"fmt"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/ctlplne/probectl/internal/secrets"
)

// CloudImportConfig selects a local file, a cloud object, or one read-only
// notification poll. The agent imports the selected data and exits.
type CloudImportConfig struct {
	Provider string             `yaml:"provider"`
	Path     string             `yaml:"path"`
	Object   *CloudObjectConfig `yaml:"object"`
	Queue    *CloudQueueConfig  `yaml:"queue"`
}

type CloudObjectConfig struct {
	Bucket        string `yaml:"bucket"`
	Key           string `yaml:"key"`
	Version       string `yaml:"version"`
	Account       string `yaml:"account"`        // Azure storage account
	Region        string `yaml:"region"`         // AWS region
	ExpectedOwner string `yaml:"expected_owner"` // AWS bucket owner's account ID
	CredentialRef string `yaml:"credential_ref"`
}

// CloudQueueConfig binds a dedicated notification subscription to a fixed
// customer-owned object scope. Only the key and immutable revision can come
// from a notification.
type CloudQueueConfig struct {
	Project       string            `yaml:"project"`
	Subscription  string            `yaml:"subscription"`
	Account       string            `yaml:"account"`
	Region        string            `yaml:"region"`
	Name          string            `yaml:"name"`
	CredentialRef string            `yaml:"credential_ref"`
	Object        CloudObjectConfig `yaml:"object"`
	Prefix        string            `yaml:"prefix"`
	StateDir      string            `yaml:"state_dir"`
}

var (
	awsFlowBucket   = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)
	awsFlowRegion   = regexp.MustCompile(`^[a-z]{2}(?:-[a-z0-9]{1,12}){1,3}-[0-9]{1,2}$`)
	awsFlowAccount  = regexp.MustCompile(`^[0-9]{12}$`)
	awsFlowQueue    = regexp.MustCompile(`^[A-Za-z0-9_-]{1,80}$`)
	azFlowAccount   = regexp.MustCompile(`^[a-z0-9]{3,24}$`)
	azFlowContainer = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,61}[a-z0-9]$`)
	gcpFlowBucket   = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{1,220}[a-z0-9]$`)
	gcpQueueProject = regexp.MustCompile(`^(?:[a-z][a-z0-9-]{4,28}[a-z0-9]|[0-9]{6,20})$`)
	gcpQueueSub     = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._~+%-]{2,254}$`)
)

func (c CloudImportConfig) Validate() error {
	switch c.Provider {
	case ProtoAWSVPCFlowLogs, ProtoAzureNSGFlowLogs, ProtoAzureVNetFlowLogs, ProtoGCPVPCFlowLogs:
	case "":
		return errors.New("flow: cloud_import.provider is required when cloud import is enabled")
	default:
		return fmt.Errorf("flow: unknown cloud_import.provider %q", c.Provider)
	}
	if c.Queue != nil {
		if c.Path != "" || c.Object != nil {
			return errors.New("flow: cloud_import.queue is mutually exclusive with path and object")
		}
		return c.Queue.validate(c.Provider)
	}
	if c.Object == nil {
		if c.Path == "" {
			return errors.New("flow: cloud_import.path is required when cloud import is enabled")
		}
		return nil
	}
	if c.Path != "" {
		return errors.New("flow: cloud_import.path and cloud_import.object are mutually exclusive")
	}
	return c.Object.validate(c.Provider)
}

func (q CloudQueueConfig) validate(provider string) error {
	switch provider {
	case ProtoGCPVPCFlowLogs:
		if q.Account != "" || q.Region != "" || q.Name != "" || !gcpQueueProject.MatchString(q.Project) ||
			!gcpQueueSub.MatchString(q.Subscription) || strings.HasPrefix(strings.ToLower(q.Subscription), "goog") {
			return errors.New("flow: GCP cloud_import.queue requires a Pub/Sub project and subscription ID")
		}
	case ProtoAWSVPCFlowLogs:
		if q.Project != "" || q.Subscription != "" || !awsFlowRegion.MatchString(q.Region) || !awsFlowAccount.MatchString(q.Account) || !awsFlowQueue.MatchString(q.Name) {
			return errors.New("flow: AWS cloud_import.queue requires an SQS standard queue name, region and 12-digit account")
		}
	case ProtoAzureNSGFlowLogs, ProtoAzureVNetFlowLogs:
		if q.Project != "" || q.Subscription != "" || q.Region != "" || !azFlowAccount.MatchString(q.Account) ||
			!azFlowContainer.MatchString(q.Name) || strings.Contains(q.Name, "--") {
			return errors.New("flow: Azure cloud_import.queue requires a storage account and queue name")
		}
	}
	if _, err := secrets.Parse(q.CredentialRef); err != nil {
		return errors.New("flow: cloud_import.queue.credential_ref must reference a configured secrets backend")
	}
	if !filepath.IsAbs(q.StateDir) || len(q.Prefix) > 768 || !strings.HasSuffix(q.Prefix, "/") || !validCloudObjectKey(q.Prefix) {
		return errors.New("flow: cloud_import.queue requires an absolute state_dir and a bounded object prefix ending in a slash")
	}
	if q.Object.Key != "" || q.Object.Version != "" {
		return errors.New("flow: cloud_import.queue.object fixes the storage scope and leaves key and version to the notification")
	}
	return q.Object.validateLocation(provider)
}

func (o CloudObjectConfig) validate(provider string) error {
	if !validCloudObjectKey(o.Key) || len(o.Version) > 1024 || strings.IndexFunc(o.Version, unicode.IsControl) >= 0 {
		return errors.New("flow: cloud_import.object requires a bounded object key and version")
	}
	if err := o.validateLocation(provider); err != nil {
		return err
	}
	if o.Version == "" {
		return nil
	}
	switch provider {
	case ProtoAWSVPCFlowLogs:
		if o.Version == "null" {
			return errors.New("flow: AWS cloud_import.object.version requires an immutable S3 version ID")
		}
	case ProtoAzureNSGFlowLogs, ProtoAzureVNetFlowLogs:
		if _, err := time.Parse(time.RFC3339Nano, o.Version); err != nil {
			return errors.New("flow: Azure cloud_import.object.version must be a Blob version ID")
		}
	case ProtoGCPVPCFlowLogs:
		if generation, err := strconv.ParseUint(o.Version, 10, 63); err != nil || generation == 0 || strconv.FormatUint(generation, 10) != o.Version {
			return errors.New("flow: GCP cloud_import.object.version must be a positive generation")
		}
	}
	return nil
}

func (o CloudObjectConfig) validateLocation(provider string) error {
	if _, err := secrets.Parse(o.CredentialRef); err != nil {
		return errors.New("flow: cloud object credential_ref must reference a configured secrets backend")
	}
	switch provider {
	case ProtoAWSVPCFlowLogs:
		if o.Account != "" || !awsFlowBucket.MatchString(o.Bucket) || !awsFlowRegion.MatchString(o.Region) || !awsFlowAccount.MatchString(o.ExpectedOwner) {
			return errors.New("flow: AWS cloud_import.object requires an S3 bucket, AWS region, and 12-digit expected_owner")
		}
	case ProtoAzureNSGFlowLogs, ProtoAzureVNetFlowLogs:
		if o.Region != "" || o.ExpectedOwner != "" || !azFlowAccount.MatchString(o.Account) || !azFlowContainer.MatchString(o.Bucket) || strings.Contains(o.Bucket, "--") {
			return errors.New("flow: Azure cloud_import.object requires a storage account and Blob container")
		}
	case ProtoGCPVPCFlowLogs:
		if o.Account != "" || o.Region != "" || o.ExpectedOwner != "" || !gcpFlowBucket.MatchString(o.Bucket) {
			return errors.New("flow: GCP cloud_import.object requires a Cloud Storage bucket")
		}
	}
	return nil
}

func validCloudObjectKey(key string) bool {
	if key == "" || len(key) > 1024 || !utf8.ValidString(key) || strings.HasPrefix(key, "/") || strings.Contains(key, "\\") ||
		strings.IndexFunc(key, unicode.IsControl) >= 0 {
		return false
	}
	for _, segment := range strings.Split(key, "/") {
		if segment == "." || segment == ".." {
			return false
		}
	}
	return true
}
