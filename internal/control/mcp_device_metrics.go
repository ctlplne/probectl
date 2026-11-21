// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"

	"github.com/ctlplne/probectl/internal/ai/mcp"
	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
)

type mcpDeviceMetricsBackend struct{ server *Server }

type nativeDeviceMetrics struct {
	Items          []deviceMetricSummary `json:"items"`
	MetricsRunning bool                  `json:"metrics_running"`
	EffectiveLimit int                   `json:"effective_limit"`
	Source         string                `json:"source,omitempty"`
}

func deviceMetricsToolOption(server *Server) (mcp.Option, error) {
	schema, err := deviceQueryToolSchema("/v1/device/metrics", 3)
	if err != nil {
		return nil, err
	}
	return mcp.WithDeviceMetricsBackend(mcpDeviceMetricsBackend{server}, schema), nil
}

func deviceSyslogPatternsToolOption(server *Server) (mcp.Option, error) {
	schema, err := deviceQueryToolSchema("/v1/device/syslog/patterns", 4)
	if err != nil {
		return nil, err
	}
	return mcp.WithDeviceSyslogPatternsBackend(mcpDeviceMetricsBackend{server}, schema), nil
}

func deviceQueryToolSchema(path string, expected int) (json.RawMessage, error) {
	var doc struct {
		Paths map[string]struct {
			Get struct {
				Parameters []struct {
					Name     string          `json:"name"`
					Required bool            `json:"required"`
					Schema   json.RawMessage `json:"schema"`
				} `json:"parameters"`
			} `json:"get"`
		} `json:"paths"`
	}
	if err := json.Unmarshal(openapiJSON, &doc); err != nil {
		return nil, err
	}
	properties := map[string]json.RawMessage{}
	var required []string
	for _, parameter := range doc.Paths[path].Get.Parameters {
		if parameter.Name != "" && json.Valid(parameter.Schema) {
			properties[parameter.Name] = parameter.Schema
			if parameter.Required {
				required = append(required, parameter.Name)
			}
		}
	}
	if len(properties) != expected {
		return nil, apierror.Internal("device query parameter contract is unavailable")
	}
	return json.Marshal(struct {
		Type                 string                     `json:"type"`
		Properties           map[string]json.RawMessage `json:"properties"`
		Required             []string                   `json:"required,omitempty"`
		AdditionalProperties bool                       `json:"additionalProperties"`
	}{Type: "object", Properties: properties, Required: required})
}

func (b mcpDeviceMetricsBackend) DeviceMetrics(ctx context.Context, actor *auth.Principal, command mcp.DeviceMetricsCommand) (json.RawMessage, error) {
	if b.server == nil {
		return nil, apierror.Unavailable("device metric service is unavailable")
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	query := url.Values{}
	if command.Device != "" {
		query.Set("device", command.Device)
	}
	if command.Metric != "" {
		query.Set("metric", command.Metric)
	}
	if command.Limit != nil {
		query.Set("limit", strconv.Itoa(*command.Limit))
	}
	// This existing concrete-handler adapter refreshes current metric/AI read
	// grants and the original credential ceiling before dispatch. No HTTP peer,
	// duplicate query implementation or report storage is involved.
	current := mcpReportBackend(b)
	result, err := invokeReportHandler[nativeDeviceMetrics](ctx, current, actor, false,
		http.MethodGet, "/v1/device/metrics?"+query.Encode(), "", nil, b.server.handleDeviceMetrics)
	if err != nil {
		return nil, err
	}
	body, err := json.Marshal(result)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(ctx context.Context) error {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return err
		}
		_, _, err := current.current(ctx, actor, false)
		return err
	}, func() {}); err != nil {
		return nil, err
	}
	// Numeric gauges stay numeric; every sender-supplied string goes through
	// ordinary native full redaction. No canonical source identity is asserted.
	return body, ctx.Err()
}

func (b mcpDeviceMetricsBackend) DeviceSyslogPatterns(ctx context.Context, actor *auth.Principal,
	command mcp.DeviceSyslogPatternsCommand) (json.RawMessage, error) {
	if b.server == nil {
		return nil, apierror.Unavailable("device syslog pattern service is unavailable")
	}
	if err := mcp.CheckOriginatingCredential(ctx); err != nil {
		return nil, err
	}
	query := url.Values{"from": {command.From}, "to": {command.To}}
	if command.Device != "" {
		query.Set("device", command.Device)
	}
	if command.Limit != nil {
		query.Set("limit", strconv.Itoa(*command.Limit))
	}
	current := mcpReportBackend(b)
	result, err := invokeReportHandler[deviceSyslogPatternPage](ctx, current, actor, false,
		http.MethodGet, "/v1/device/syslog/patterns?"+query.Encode(), "", nil, b.server.handleListDeviceSyslogPatterns)
	if err != nil {
		return nil, err
	}
	if err := mcp.RetainNativePublication(ctx, func(ctx context.Context) error {
		if err := mcp.CheckOriginatingCredential(ctx); err != nil {
			return err
		}
		_, _, err := current.current(ctx, actor, false)
		return err
	}, func() {}); err != nil {
		return nil, err
	}
	return json.Marshal(result)
}
