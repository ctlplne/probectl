// SPDX-License-Identifier: LicenseRef-Probectl-Commercial
//
// Licensed under the probectl Commercial Source License; see ee/LICENSE.
// Production use requires a valid commercial agreement; resale additionally
// requires an MSP entitlement and reseller agreement.

package rmm

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
)

var errNinjaOneAuth = errors.New("rmm: NinjaOne monitoring credential unavailable")

type ninjaOneCredential struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

func ninjaOneMonitoringToken(ctx context.Context, client *http.Client, origin string, raw []byte) (string, error) {
	var credential ninjaOneCredential
	if !decodeRMMJSON(raw, &credential) || credential.ClientID == "" || credential.ClientSecret == "" {
		return "", errNinjaOneAuth
	}
	form := url.Values{
		"grant_type": {"client_credentials"}, "scope": {"monitoring"},
		"client_id": {credential.ClientID}, "client_secret": {credential.ClientSecret},
	}
	endpoint, err := url.JoinPath(origin, "ws", "oauth", "token")
	if err != nil {
		return "", errNinjaOneAuth
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", errNinjaOneAuth
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	response, err := client.Do(req)
	if err != nil {
		return "", errNinjaOneAuth
	}
	defer func() { _ = response.Body.Close() }()
	const maxTokenResponse = 32 << 10
	var token struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
		Scope       string `json:"scope"`
	}
	wire, err := io.ReadAll(io.LimitReader(response.Body, maxTokenResponse+1))
	if response.StatusCode != http.StatusOK || err != nil || len(wire) > maxTokenResponse ||
		json.Unmarshal(wire, &token) != nil || !strings.EqualFold(token.TokenType, "Bearer") ||
		token.Scope != "monitoring" || len(token.AccessToken) > 16384 || !rmmBearerToken.MatchString(token.AccessToken) {
		return "", errNinjaOneAuth
	}
	return token.AccessToken, nil
}
