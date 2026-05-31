package control

import (
	"encoding/json"
	"net/http"
)

// writeJSON serializes body as JSON with the given status code. Encoding errors
// are ignored: the status line is already committed, so there is nothing useful
// to do but stop writing.
func writeJSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}
