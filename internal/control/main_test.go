// SPDX-License-Identifier: LicenseRef-probectl-TBD

package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/imfeelingtheagi/probectl/internal/apierror"
	"github.com/imfeelingtheagi/probectl/internal/auth"
	"github.com/imfeelingtheagi/probectl/internal/config"
	"github.com/imfeelingtheagi/probectl/internal/logging"
	"github.com/imfeelingtheagi/probectl/internal/store"
	"github.com/imfeelingtheagi/probectl/internal/tenancy"
)

func TestMain(m *testing.M) {
	// Keep test output clean: discard server logs.
	slog.SetDefault(slog.New(slog.NewTextHandler(io.Discard, nil)))
	os.Exit(m.Run())
}

// The TEST binary installs its own dev-auth hook so the handler suites
// (cfg.AuthMode="dev") run without the devauth build tag. _test.go files are
// never part of a shipped binary, so this mirrors internal/control/devauth.go
// without weakening the release guarantee (RED-001).
func init() { devModeHook = testDevAuthHook }

func testDevAuthHook(_ *Server, w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	tid := tenancy.DefaultTenantID
	if h := r.Header.Get("X-Probectl-Tenant"); h != "" {
		if !uuidRe.MatchString(h) {
			writeError(w, r, apierror.BadRequest("X-Probectl-Tenant must be a tenant UUID"))
			return nil, true
		}
		tid = tenancy.ID(h)
	}
	perms := make(map[string]bool, len(allPermissionKeys))
	for _, k := range allPermissionKeys {
		perms[k] = true
	}
	return &auth.Principal{
		TenantID:       tid.String(),
		UserID:         "dev",
		Email:          "dev@probectl.local",
		DisplayName:    "Dev",
		TimeZone:       "UTC",
		Locale:         "en",
		TenantTimeZone: "UTC",
		TenantLocale:   "en",
		Permissions:    perms,
		Attributes:     map[string]string{"mfa": "true"},
	}, false
}

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func testServer(pinger store.Pinger) *Server {
	cfg := &config.Config{
		HTTPAddr:    ":0",
		HSTSEnabled: true,
		HSTSMaxAge:  time.Hour,
		AuthMode:    "dev",
	}
	return New(cfg, logging.New(io.Discard, "error", "json"), pinger, nil, nil, nil)
}
