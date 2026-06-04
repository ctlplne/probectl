package browser

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/imfeelingtheagi/probectl/internal/objectstore"
)

// loginApp is a tiny local app with a real login flow: GET /login renders a form,
// POST /login sets a session cookie on the right credentials, GET /dashboard needs
// the cookie. It's the "local app" the scripted-login integration test runs against.
func loginApp() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			_, _ = w.Write([]byte(`<form method=post><input name=username><input name=password></form>`))
			return
		}
		_ = r.ParseForm()
		if r.PostForm.Get("username") == "alice" && r.PostForm.Get("password") == "secret" {
			http.SetCookie(w, &http.Cookie{Name: "session", Value: "ok", Path: "/"})
			_, _ = w.Write([]byte(`<h1>Welcome alice</h1>`))
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = w.Write([]byte(`<h1>Invalid credentials</h1>`))
	})
	mux.HandleFunc("/dashboard", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err != nil || c.Value != "ok" {
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte("Unauthorized"))
			return
		}
		_, _ = w.Write([]byte(`<h1>Dashboard for alice</h1>`))
	})
	return httptest.NewServer(mux)
}

func loginSteps(password string) []Step {
	return []Step{
		{Name: "open login", Action: Goto},
		{Name: "username", Action: Fill, Field: "username", Value: "alice"},
		{Name: "password", Action: Fill, Field: "password", Value: password},
		{Name: "submit", Action: Submit},
		{Name: "welcome", Action: AssertText, Value: "Welcome"},
		{Name: "status", Action: AssertStatus, Status: 200},
		{Name: "dashboard", Action: Goto},
		{Name: "loaded", Action: AssertText, Value: "Dashboard"},
	}
}

// A scripted login against the local app reports step timings + a resource
// waterfall, and a wrong password yields a failure with a captured artifact —
// the S36 "Done when".
func TestHTTPDriverScriptedLoginSuccess(t *testing.T) {
	app := loginApp()
	defer app.Close()

	steps := loginSteps("secret")
	steps[3].URL = app.URL + "/login" // submit target
	steps[6].URL = app.URL + "/dashboard"
	s := Script{Name: "login", StartURL: app.URL + "/login", Steps: steps}

	out, err := NewHTTPDriver().Run(context.Background(), s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	r := out.Result
	if !r.Success {
		t.Fatalf("login should succeed: %+v", r)
	}
	if len(r.Steps) != 8 {
		t.Fatalf("want 8 step results, got %d", len(r.Steps))
	}
	// A waterfall with the GET /login, POST /login, GET /dashboard requests.
	if len(r.Waterfall) < 3 {
		t.Fatalf("waterfall should have >=3 resources, got %d", len(r.Waterfall))
	}
	for _, rt := range r.Waterfall {
		if rt.Status == 0 || rt.URL == "" {
			t.Fatalf("waterfall entry missing status/url: %+v", rt)
		}
	}
	if out.Screenshot != nil {
		t.Fatal("success run should not capture an artifact")
	}
}

func TestHTTPDriverScriptedLoginFailureCaptured(t *testing.T) {
	app := loginApp()
	defer app.Close()

	steps := loginSteps("WRONG")
	steps[3].URL = app.URL + "/login"
	steps[6].URL = app.URL + "/dashboard"
	s := Script{Name: "login", StartURL: app.URL + "/login", Steps: steps}

	// Drive it through the Fleet so the failure artifact lands in the object store.
	store := objectstore.NewMemory()
	fleet := NewFleet(Config{MaxConcurrency: 1}, func() Driver { return NewHTTPDriver() }, store, quiet())
	defer fleet.Close()

	r, err := fleet.Run(context.Background(), "t1", s)
	if err != nil {
		t.Fatalf("run: %v", err)
	}
	if r.Success {
		t.Fatal("wrong password should fail the transaction")
	}
	if !strings.Contains(r.Error, "welcome") && !strings.Contains(r.Error, "Welcome") {
		t.Fatalf("error should name the failing assert step, got %q", r.Error)
	}
	// The failure artifact is stored under the tenant prefix and is retrievable.
	if r.Screenshot == nil || !strings.HasPrefix(r.Screenshot.Key, "tenant/t1/browser/") {
		t.Fatalf("expected a tenant-scoped artifact ref, got %+v", r.Screenshot)
	}
	obj, err := store.Get(context.Background(), r.Screenshot.Key)
	if err != nil {
		t.Fatalf("artifact get: %v", err)
	}
	if !strings.Contains(string(obj.Data), "Invalid credentials") {
		t.Fatalf("artifact should capture the failed page, got %q", obj.Data)
	}
}
