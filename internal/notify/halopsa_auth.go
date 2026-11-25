// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package notify

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"
)

// HaloCredentials are the application credentials for one configured Halo connection.
type HaloCredentials struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
	Scope        string `json:"scope"`
}

// HaloAPI implements the common Halo OAuth and REST transport. Each caller
// supplies only relative paths against its own configured TLS origin.
type HaloAPI struct {
	origin *url.URL
	auth   haloOAuth
}

func NewHaloAPI(endpoint string, credentials HaloCredentials, client Doer) (*HaloAPI, error) {
	origin, err := psaHTTPSURL(endpoint)
	if err != nil || (origin.Path != "" && origin.Path != "/") {
		return nil, errors.New("halopsa: configure the HTTPS Halo instance origin")
	}
	if strings.TrimSpace(credentials.ClientID) == "" || strings.TrimSpace(credentials.ClientSecret) == "" {
		return nil, errors.New("halopsa: OAuth credentials are incomplete")
	}
	credentials.Scope = strings.TrimSpace(credentials.Scope)
	if credentials.Scope == "" {
		credentials.Scope = "all"
	}
	return &HaloAPI{
		origin: origin,
		auth: haloOAuth{
			endpoint: origin.JoinPath("auth", "token").String(), credentials: credentials,
			client: clientWithoutRedirects(client),
		},
	}, nil
}

// Get reads and decodes a single bounded Halo API response.
func (c *HaloAPI) Get(ctx context.Context, result any, query url.Values, resource ...string) error {
	body, err := c.request(ctx, http.MethodGet, query, nil, resource, nil)
	if err != nil {
		return err
	}
	if json.Unmarshal(body, result) != nil {
		return errors.New("halopsa: invalid resource response")
	}
	return nil
}

// Post sends one payload to the configured Halo instance. It checks any
// supplied write guard after obtaining the OAuth token.
func (c *HaloAPI) Post(ctx context.Context, payload any, beforeSend func() error, resource ...string) ([]byte, error) {
	body, err := json.Marshal(payload)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errHaloPostNotSent, err)
	}
	return c.request(ctx, http.MethodPost, nil, body, resource, beforeSend)
}

var errHaloPostNotSent = errors.New("halopsa: API write did not reach its request step")

func (c *HaloAPI) request(ctx context.Context, method string, query url.Values, body []byte, resource []string, beforeSend func() error) ([]byte, error) {
	headers, err := c.auth.headers(ctx)
	if err != nil {
		if method == http.MethodPost {
			return nil, fmt.Errorf("%w: %w", errHaloPostNotSent, err)
		}
		return nil, err
	}
	u := c.origin.JoinPath(append([]string{"api"}, resource...)...)
	u.RawQuery = query.Encode()
	if beforeSend != nil {
		if err := beforeSend(); err != nil {
			return nil, fmt.Errorf("%w: %w", errHaloPostNotSent, err)
		}
	}
	result, err := doJSONBytes(ctx, c.auth.client, method, u.String(), headers, body)
	c.auth.discardUnauthorized(headers["Authorization"], err)
	return result, err
}

// One Halo connection owns one token cache. It is never keyed on the Halo
// origin alone because multiple tenants can use the same Halo instance.
type haloOAuth struct {
	endpoint    string
	credentials HaloCredentials
	client      Doer

	mu        sync.Mutex
	token     string
	refreshAt time.Time
}

var haloBearerToken = regexp.MustCompile(`^[A-Za-z0-9._~+/-]+=*$`)

func (c *haloOAuth) headers(ctx context.Context) (map[string]string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	now := time.Now()
	if c.token == "" || !now.Before(c.refreshAt) {
		form := url.Values{
			"grant_type":    {"client_credentials"},
			"client_id":     {c.credentials.ClientID},
			"client_secret": {c.credentials.ClientSecret},
			"scope":         {c.credentials.Scope},
		}
		data, err := doJSONBytes(ctx, c.client, http.MethodPost, c.endpoint,
			map[string]string{"Content-Type": "application/x-www-form-urlencoded"}, []byte(form.Encode()))
		if err != nil {
			return nil, err
		}
		var reply struct {
			Token     string `json:"access_token"`
			Type      string `json:"token_type"`
			ExpiresIn int64  `json:"expires_in"`
		}
		if json.Unmarshal(data, &reply) != nil || !strings.EqualFold(reply.Type, "Bearer") ||
			!haloBearerToken.MatchString(reply.Token) || reply.ExpiresIn <= 0 ||
			reply.ExpiresIn > math.MaxInt64/int64(time.Second) {
			return nil, errors.New("halopsa: invalid OAuth token response")
		}
		ttl := time.Duration(reply.ExpiresIn) * time.Second
		c.token = reply.Token
		c.refreshAt = now.Add(ttl - ttl/10)
	}
	return map[string]string{"Authorization": "Bearer " + c.token}, nil
}

// discardUnauthorized drops only the rejected token. An in-flight response
// cannot discard a newer token, and a write is never replayed here.
func (c *haloOAuth) discardUnauthorized(authorization string, err error) {
	var status httpStatusError
	if !errors.As(err, &status) || status.status != http.StatusUnauthorized {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if authorization == "Bearer "+c.token {
		c.token = ""
	}
}
