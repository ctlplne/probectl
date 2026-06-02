package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHandleAIAuthor(t *testing.T) {
	h := testServer(nil).Handler()

	// A concrete prompt → a schema-valid HTTP proposal (air-gapped heuristic).
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{"prompt": "monitor https://api.example.com/health"}))
	if rec.Code != http.StatusOK {
		t.Fatalf("author: status %d body %s", rec.Code, rec.Body.String())
	}
	var prop struct {
		Spec struct {
			Type   string `json:"type"`
			Target string `json:"target"`
		} `json:"spec"`
		Source string `json:"source"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &prop); err != nil {
		t.Fatal(err)
	}
	if prop.Spec.Type != "http" || prop.Source == "" {
		t.Errorf("proposal = %+v", prop)
	}

	// Empty prompt → 422.
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{"prompt": "  "}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("empty prompt: status %d, want 422", rec.Code)
	}

	// A target-less prompt → 422 (could not author; propose nothing rather than guess).
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/author", map[string]any{"prompt": "make everything good"}))
	if rec.Code != http.StatusUnprocessableEntity {
		t.Errorf("target-less prompt: status %d, want 422", rec.Code)
	}
}

func TestHandleAIDiscoverNoData(t *testing.T) {
	h := testServer(nil).Handler()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, aiTestReq(http.MethodPost, "/v1/ai/discover", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("discover: status %d body %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Proposals []any `json:"proposals"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Proposals) != 0 {
		t.Errorf("with no data there should be no proposals, got %v", out.Proposals)
	}
}
