// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"net/http"

	"github.com/ctlplne/probectl/internal/apierror"
)

// lifecycleDownloadWriter commits attachment headers only when an actual body
// begins. Pre-output failures retain the ordinary API error response. After any
// output, failure must abort the transport, even if a small gzip body is already
// complete: a final audit/authority refusal cannot become a successful download.
type lifecycleDownloadWriter struct {
	destination http.ResponseWriter
	filename    string
	started     bool
}

func (w *lifecycleDownloadWriter) Write(body []byte) (int, error) {
	if len(body) == 0 {
		return 0, nil
	}
	if !w.started {
		w.destination.Header().Set("Content-Type", "application/gzip")
		w.destination.Header().Set("Content-Disposition", `attachment; filename="`+w.filename+`"`)
		w.started = true
	}
	return w.destination.Write(body)
}

func (w *lifecycleDownloadWriter) finish(err error) error {
	if err != nil {
		if w.started {
			panic(http.ErrAbortHandler)
		}
		return err
	}
	if !w.started {
		return apierror.Internal("export produced no bundle")
	}
	return nil
}
