// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package crypto

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"slices"
	"strings"
	"time"
)

type AWSV4Credentials struct {
	AccessKey    string
	SecretKey    []byte
	SessionToken string
}

// DecodeAWSV4Credentials decodes the shared secrets-backed AWS read identity.
// The caller zeroizes SecretKey when the cloud request sequence ends.
func DecodeAWSV4Credentials(raw []byte) (AWSV4Credentials, error) {
	var value struct {
		AccessKey    string `json:"access_key_id"`
		SecretKey    string `json:"secret_access_key"`
		SessionToken string `json:"session_token"`
	}
	if len(raw) > 32<<10 || json.Unmarshal(raw, &value) != nil || len(value.AccessKey) < 16 || len(value.AccessKey) > 128 ||
		strings.IndexFunc(value.AccessKey, func(r rune) bool { return (r < 'A' || r > 'Z') && (r < '0' || r > '9') }) >= 0 ||
		value.SecretKey == "" || !awsHeaderValue(value.SecretKey) || !awsHeaderValue(value.SessionToken) {
		return AWSV4Credentials{}, errors.New("crypto: invalid AWS read credential")
	}
	return AWSV4Credentials{AccessKey: value.AccessKey, SecretKey: []byte(value.SecretKey), SessionToken: value.SessionToken}, nil
}

func awsHeaderValue(s string) bool {
	return strings.IndexFunc(s, func(r rune) bool { return r < '!' || r > '~' }) < 0
}

// AWSRegionalHost returns the commercial or China partition regional endpoint
// for an AWS service and region already validated by the caller.
func AWSRegionalHost(service, region string) string {
	suffix := ".amazonaws.com"
	if strings.HasPrefix(region, "cn-") {
		suffix += ".cn"
	}
	return service + "." + region + suffix
}

// SignAWSV4 signs the request and its explicit service-specific headers. The
// caller supplies the final AWS URI encoding and the exact bytes to transmit.
func SignAWSV4(req *http.Request, body []byte, creds AWSV4Credentials, region, service string, now time.Time, headers ...string) {
	now = now.UTC()
	amzDate, date := now.Format("20060102T150405Z"), now.Format("20060102")
	requestHash := hex.EncodeToString(Hash(body))
	req.Header.Set("X-Amz-Date", amzDate)
	if slices.Contains(headers, "x-amz-content-sha256") {
		req.Header.Set("X-Amz-Content-Sha256", requestHash)
	}
	names := append([]string{"host", "x-amz-date"}, headers...)
	if creds.SessionToken != "" {
		req.Header.Set("X-Amz-Security-Token", creds.SessionToken)
		names = append(names, "x-amz-security-token")
	}
	slices.Sort(names)
	names = slices.Compact(names)
	var canonicalHeaders strings.Builder
	for _, name := range names {
		value := req.Header.Get(name)
		if name == "host" {
			value = req.URL.Host
		}
		canonicalHeaders.WriteString(name + ":" + strings.Join(strings.Fields(value), " ") + "\n")
	}
	canonicalQuery := strings.ReplaceAll(req.URL.Query().Encode(), "+", "%20")
	signedHeaders := strings.Join(names, ";")
	canonicalRequest := strings.Join([]string{
		req.Method, req.URL.EscapedPath(), canonicalQuery, canonicalHeaders.String(), signedHeaders, requestHash,
	}, "\n")
	scope := date + "/" + region + "/" + service + "/aws4_request"
	stringToSign := strings.Join([]string{"AWS4-HMAC-SHA256", amzDate, scope, hex.EncodeToString(Hash([]byte(canonicalRequest)))}, "\n")
	seed := append([]byte("AWS4"), creds.SecretKey...)
	defer Zeroize(seed)
	key := Sign(seed, []byte(date))
	for _, scopePart := range []string{region, service, "aws4_request"} {
		next := Sign(key, []byte(scopePart))
		Zeroize(key)
		key = next
	}
	defer Zeroize(key)
	signature := hex.EncodeToString(Sign(key, []byte(stringToSign)))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+creds.AccessKey+"/"+scope+", SignedHeaders="+signedHeaders+", Signature="+signature)
}
