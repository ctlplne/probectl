// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package topology

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"time"

	"github.com/ctlplne/probectl/internal/crypto"
	"github.com/ctlplne/probectl/internal/secrets"
)

var cloudInventoryOAuthToken = regexp.MustCompile(`^[a-zA-Z0-9_.~+/\-]+=*$`)

func cloudInventoryHTTPClient() *http.Client {
	client := crypto.HardenedHTTPClient(20 * time.Second)
	client.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return client
}

func resolveCloudInventoryOAuth(ctx context.Context, resolver *secrets.Resolver, ref string) ([]byte, func(), error) {
	if _, err := secrets.Parse(ref); err != nil {
		return nil, nil, errors.New("topology: cloud inventory requires a credential reference")
	}
	raw, release, err := resolver.ResolveBytesUncached(ctx, ref)
	if err != nil {
		return nil, nil, errors.New("topology: cloud inventory credential could not be resolved")
	}
	credential := bytes.TrimSpace(raw)
	if len(credential) > 8192 || !cloudInventoryOAuthToken.Match(credential) {
		release()
		return nil, nil, errors.New("topology: cloud inventory requires an OAuth access token")
	}
	return credential, release, nil
}

func readCloudInventoryResponse(client *http.Client, req *http.Request) ([]byte, error) {
	resp, err := client.Do(req)
	if err != nil {
		return nil, errors.New("request failed")
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("returned HTTP %d", resp.StatusCode)
	}
	if resp.ContentLength > cloudInventoryPageBytes {
		return nil, errors.New("response exceeded its byte budget")
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, cloudInventoryPageBytes+1))
	if err != nil || len(body) > cloudInventoryPageBytes || (resp.ContentLength >= 0 && resp.ContentLength != int64(len(body))) {
		return nil, errors.New("response could not be read within its byte budget")
	}
	return body, nil
}
