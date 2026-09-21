// SPDX-License-Identifier: BUSL-1.1
//
// Use of this source code is governed by the Business Source License 1.1
// in the LICENSE file at the root of this repository; on its Change Date
// each version converts to the Mozilla Public License 2.0.

package config

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log/slog"
	"reflect"
	"strings"
	"testing"
)

// TestLogValueEmitsOnlyAllowlistedFields (DPR-244) is the CodeQL
// go/clear-text-logging finding turned into a property.
//
// cmd/probectl-control logs the whole config at startup —
// `log.Info("starting probectl-control", …, "config", cfg)` — and CodeQL reports
// BusSASLPassword, ObjectStoreS3SecretKey and AlertSMTPPassword reaching a
// logging call, because it does not model slog.LogValuer. Config DOES implement
// it, as a 13-field allowlist, so the finding is a false positive.
//
// What was NOT true is that anything tested it. The only existing test covered the
// database URL, and the allowlist's stated safety property — "a new secret field
// added later cannot leak because it is simply not on the list" — rested on a
// hand-maintained list with nothing checking it. §7.6 says secrets are never
// logged, so that property deserves a test rather than a comment.
//
// This sets EVERY string, []byte and []string field in Config to a sentinel
// naming itself, logs the config, and requires that any sentinel which surfaces
// belongs to a field explicitly declared loggable here. A new secret field is
// therefore safe by default and a new field added to LogValue has to be declared
// — which is the direction the failure should point.
func TestLogValueEmitsOnlyAllowlistedFields(t *testing.T) {
	// The fields LogValue is allowed to surface verbatim. Anything else that
	// appears is a leak; anything here that stops appearing is a behavior change
	// worth noticing.
	loggable := map[string]bool{
		"HTTPAddr": true,
		"LogLevel": true, "LogFormat": true,
		"BusMode": true, "TSDBMode": true,
		// DatabaseURL surfaces DELIBERATELY and redacted (redactURL); its own
		// test, TestLogValueRedactsPassword, covers what must be stripped from it.
		"DatabaseURL": true,
	}

	cfg := &Config{}
	sentinels := map[string]string{}
	v := reflect.ValueOf(cfg).Elem()
	rt := v.Type()
	for i := 0; i < rt.NumField(); i++ {
		f := rt.Field(i)
		if !v.Field(i).CanSet() {
			continue
		}
		s := fmt.Sprintf("SENTINEL-%s-VALUE", f.Name)
		switch v.Field(i).Interface().(type) {
		case string:
			v.Field(i).SetString(s)
		case []byte:
			v.Field(i).SetBytes([]byte(s))
		case []string:
			v.Field(i).Set(reflect.ValueOf([]string{s}))
		default:
			continue
		}
		sentinels[f.Name] = s
	}
	if len(sentinels) < 40 {
		t.Fatalf("only populated %d fields; the reflection walk has stopped covering Config", len(sentinels))
	}

	var buf bytes.Buffer
	slog.New(slog.NewJSONHandler(&buf, nil)).Info("startup", "config", cfg)
	out := buf.String()

	var leaked []string
	for name, s := range sentinels {
		if !strings.Contains(out, s) {
			continue
		}
		if !loggable[name] {
			leaked = append(leaked, name)
		}
	}
	if len(leaked) != 0 {
		t.Errorf("Config.LogValue surfaced %d field(s) that are not declared loggable — §7 guardrail 6 "+
			"says secrets are never logged, and this is the allowlist that keeps that true: %v\nlogged: %s",
			len(leaked), leaked, out)
	}
	// And the three CodeQL named, by name, so the finding's own claim is pinned.
	for _, name := range []string{"BusSASLPassword", "ObjectStoreS3SecretKey", "AlertSMTPPassword"} {
		if s, ok := sentinels[name]; !ok {
			t.Errorf("%s is no longer a settable Config field; update this test", name)
		} else if strings.Contains(out, s) {
			t.Errorf("%s reached the startup log — the exact leak CodeQL go/clear-text-logging reports", name)
		}
	}
}

// TestRedactedEmitsNoSecretMaterial (DPR-244): the support bundle's snapshot
// makes the same promise in its own comment — "NO secret field … is ever
// reflected — a new secret field added later cannot leak because it is simply not
// on the list". Same technique, same reason: a support bundle leaves the
// deployment.
func TestRedactedEmitsNoSecretMaterial(t *testing.T) {
	// Fields holding secret MATERIAL. Paths and key ids are deliberately absent:
	// a filename is not a credential, and the bundle names them on purpose.
	secretMaterial := []string{
		"EnvelopeKey", "EnvelopeOpenerKeys", "BusSASLPassword", "WormSigningKey",
		"IRUnlockKey", "ObjectStoreS3AccessKey", "ObjectStoreS3SecretKey",
		"ObjectStoreS3SessionToken", "EvidenceSigningKey", "AlertSMTPPassword",
		"SessionHMACKey", "OIDCClientSecret", "CMDBSecret", "OTLPFreshnessHMACKey",
		"OTLPExportToken", "AIModelToken", "OutageRadarToken",
		"ProviderBootstrapToken", "SIEMToken",
	}
	cfg := &Config{}
	v := reflect.ValueOf(cfg).Elem()
	want := map[string]string{}
	for _, name := range secretMaterial {
		f := v.FieldByName(name)
		if !f.IsValid() {
			t.Fatalf("%s is no longer a Config field; update this test rather than dropping the check", name)
		}
		s := fmt.Sprintf("SENTINEL-%s-VALUE", name)
		switch f.Interface().(type) {
		case string:
			f.SetString(s)
		case []byte:
			f.SetBytes([]byte(s))
		default:
			t.Fatalf("%s has an unexpected type %s", name, f.Type())
		}
		want[name] = s
	}
	raw, err := json.Marshal(cfg.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	out := string(raw)
	for name, s := range want {
		if strings.Contains(out, s) {
			t.Errorf("%s reached the support-bundle snapshot: %s", name, out)
		}
	}
}
