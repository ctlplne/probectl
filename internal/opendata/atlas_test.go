package opendata

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
)

func TestNoopSchedulerDisabled(t *testing.T) {
	_, err := NoopScheduler{}.Schedule(context.Background(), MeasurementSpec{})
	if !errors.Is(err, ErrAtlasDisabled) {
		t.Errorf("err = %v, want ErrAtlasDisabled", err)
	}
}

func TestAtlasClientWithoutKeyIsDisabled(t *testing.T) {
	_, err := NewAtlasClient("", nil).Schedule(context.Background(), MeasurementSpec{Type: "ping", Target: "1.1.1.1"})
	if !errors.Is(err, ErrAtlasDisabled) {
		t.Errorf("err = %v, want ErrAtlasDisabled", err)
	}
}

func TestAtlasClientSchedule(t *testing.T) {
	doer := &fakeDoer{fn: func(req *http.Request) (*http.Response, error) {
		if req.Method != http.MethodPost {
			t.Errorf("method = %s", req.Method)
		}
		if req.Header.Get("Authorization") != "Key secret-key" {
			t.Errorf("auth = %q", req.Header.Get("Authorization"))
		}
		body, _ := io.ReadAll(req.Body)
		if !strings.Contains(string(body), `"target":"1.1.1.1"`) || !strings.Contains(string(body), `"is_oneoff":true`) {
			t.Errorf("body = %s", body)
		}
		return jsonResp(http.StatusCreated, `{"measurements":[101,102]}`), nil
	}}
	res, err := NewAtlasClient("secret-key", doer).Schedule(context.Background(),
		MeasurementSpec{Type: "ping", Target: "1.1.1.1", ProbeCount: 3})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.MeasurementIDs) != 2 || res.MeasurementIDs[0] != 101 {
		t.Errorf("ids = %v", res.MeasurementIDs)
	}
}

func TestAtlasClientErrorStatus(t *testing.T) {
	doer := &fakeDoer{fn: func(*http.Request) (*http.Response, error) {
		return jsonResp(http.StatusForbidden, `{"error":"no credits"}`), nil
	}}
	if _, err := NewAtlasClient("k", doer).Schedule(context.Background(),
		MeasurementSpec{Type: "ping", Target: "1.1.1.1"}); err == nil {
		t.Fatal("a non-2xx status should error")
	}
}
