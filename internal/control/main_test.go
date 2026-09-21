// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package control

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ctlplne/probectl/internal/apierror"
	"github.com/ctlplne/probectl/internal/auth"
	"github.com/ctlplne/probectl/internal/config"
	"github.com/ctlplne/probectl/internal/logging"
	"github.com/ctlplne/probectl/internal/store"
	"github.com/ctlplne/probectl/internal/tenancy"
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

// testWithholdPermissionsHeader lets a test drop specific permissions from
// the dev principal for one request (test-binary only: this hook is installed
// by main_test.go and never exists in a shipped binary).
const testWithholdPermissionsHeader = "X-Probectl-Test-Withhold-Permissions"

func testDevAuthHook(_ *Server, w http.ResponseWriter, r *http.Request) (*auth.Principal, bool) {
	tid := tenancy.DefaultTenantID
	if h := r.Header.Get("X-Probectl-Tenant"); h != "" {
		if !uuidRe.MatchString(h) {
			writeError(w, r, apierror.BadRequest("X-Probectl-Tenant must be a tenant UUID"))
			return nil, true
		}
		tid = tenancy.ID(h)
	}
	// S-e0e73b57: the dev principal normally holds every permission, which
	// makes requirePermission a pass-through for the handler suites. A test
	// may narrow it for ONE request by naming the permissions it wants
	// withheld, so an authorization refusal can actually be observed.
	perms := make(map[string]bool, len(allPermissionKeys))
	withheld := map[string]bool{}
	for _, k := range strings.Split(r.Header.Get(testWithholdPermissionsHeader), ",") {
		if k = strings.TrimSpace(k); k != "" {
			withheld[k] = true
		}
	}
	for _, k := range allPermissionKeys {
		if !withheld[k] {
			perms[k] = true
		}
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
