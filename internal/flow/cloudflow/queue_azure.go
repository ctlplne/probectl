// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package cloudflow

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"encoding/xml"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/ctlplne/probectl/internal/flow"
)

func (source cloudObjectTransfer) azureQueuePeek(ctx context.Context, q flow.CloudQueueConfig, credential string) (queueNotices, error) {
	var result queueNotices
	if !visibleASCIICredential(credential) {
		return result, errors.New("cloudflow: invalid Azure Queue access token")
	}
	u := url.URL{Scheme: "https", Host: q.Account + ".queue.core.windows.net", Path: "/" + q.Name + "/messages"}
	u.RawQuery = url.Values{"peekonly": {"true"}, "numofmessages": {strconv.Itoa(queueMaxMessages)}}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return result, errors.New("cloudflow: cannot construct the Azure Queue peek request")
	}
	req.Header.Set("Authorization", "Bearer "+credential)
	req.Header.Set("X-Ms-Version", "2023-11-03")
	req.Header.Set("X-Ms-Date", time.Now().UTC().Format(http.TimeFormat))
	body, err := source.readQueueResponse(req, "Azure Queue peek")
	if err != nil {
		return result, err
	}
	return decodeAzureQueueMessages(body, q.Object.Account)
}

func decodeAzureQueueMessages(body []byte, account string) (queueNotices, error) {
	decoder := xml.NewDecoder(bytes.NewReader(body))
	var result queueNotices
	var opened bool
	count := 0
	invalid := errors.New("cloudflow: invalid Azure Queue peek response")
	for {
		token, err := decoder.Token()
		if err != nil {
			return queueNotices{}, invalid
		}
		switch token := token.(type) {
		case xml.StartElement:
			if !opened {
				if token.Name.Local != "QueueMessagesList" {
					return queueNotices{}, invalid
				}
				opened = true
				continue
			}
			if token.Name.Local != "QueueMessage" {
				if err := decoder.Skip(); err != nil {
					return queueNotices{}, invalid
				}
				continue
			}
			if count == queueMaxMessages {
				return queueNotices{}, errQueueBatchLimit
			}
			count++
			var message struct {
				Text string `xml:"MessageText"`
			}
			if err := decoder.DecodeElement(&message, &token); err != nil {
				return queueNotices{}, invalid
			}
			if err := result.addAzureRecords(account, message.Text); err != nil {
				return queueNotices{}, err
			}
		case xml.EndElement:
			if !azureQueueEnvelopeComplete(decoder) {
				return queueNotices{}, invalid
			}
			return result, nil
		case xml.CharData:
			if len(bytes.Trim(token, " \t\r\n")) != 0 {
				return queueNotices{}, invalid
			}
		case xml.Directive:
			return queueNotices{}, invalid
		}
	}
}

// A valid list can end in whitespace or comments. Validate the rest of the
// response before publishing any notices from the list.
func azureQueueEnvelopeComplete(decoder *xml.Decoder) bool {
	for {
		token, err := decoder.Token()
		if err != nil {
			return errors.Is(err, io.EOF)
		}
		switch token := token.(type) {
		case xml.CharData:
			if len(bytes.Trim(token, " \t\r\n")) == 0 {
				continue
			}
		case xml.Comment:
			continue
		}
		return false
	}
}

type azureQueueEvent struct {
	EventType string `json:"eventType"` // Event Grid schema
	EventTime string `json:"eventTime"`
	Type      string `json:"type"` // CloudEvents schema
	Time      string `json:"time"`
	Data      struct {
		URL  string `json:"url"`
		ETag string `json:"eTag"`
	} `json:"data"`
}

func (n *queueNotices) addAzureRecords(account, message string) error {
	remaining := queueMaxNotices - len(n.objects) - n.skipped
	if remaining < 1 {
		return errQueueBatchLimit
	}
	body := strings.TrimSpace(message)
	if body == "" || (body[0] != '[' && body[0] != '{') {
		raw, err := base64.StdEncoding.DecodeString(body)
		if err != nil {
			n.skipped++
			return nil
		}
		body = strings.TrimSpace(string(raw))
	}
	var events []azureQueueEvent
	if strings.HasPrefix(body, "{") {
		var one azureQueueEvent
		if json.Unmarshal([]byte(body), &one) == nil {
			events = append(events, one)
		}
	} else {
		var err error
		events, err = decodeQueueArray[azureQueueEvent]([]byte(body), remaining)
		if errors.Is(err, errQueueBatchLimit) {
			return err
		}
	}
	if len(events) == 0 {
		n.skipped++
		return nil
	}
	for _, event := range events {
		clock := event.EventTime
		if event.EventType == "" {
			event.EventType, clock = event.Type, event.Time
		}
		u, err := url.Parse(event.Data.URL)
		if event.EventType != "Microsoft.Storage.BlobCreated" || err != nil || !scopedAzureBlobURL(u, account) {
			n.skipped++
			continue
		}
		bucket, key, _ := strings.Cut(strings.TrimPrefix(u.Path, "/"), "/")
		n.objects = append(n.objects, objectNotice{bucket: bucket, key: key, etag: strongNoticeETag(event.Data.ETag), clock: clock})
	}
	return nil
}

func scopedAzureBlobURL(u *url.URL, account string) bool {
	return u.Scheme == "https" && u.Opaque == "" && u.User == nil && u.RawQuery == "" && !u.ForceQuery && u.Fragment == "" &&
		(u.Host == account+".blob.core.windows.net" || u.Host == account+".dfs.core.windows.net")
}
