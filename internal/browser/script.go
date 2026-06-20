// SPDX-License-Identifier: LicenseRef-probectl-TBD

// Package browser is probectl's browser/transaction synthetic (S36, F15): scripted
// multi-step transactions (a login, a checkout) run by a managed worker fleet,
// capturing a per-resource waterfall, DOM/paint timings, step timings, and a
// failure screenshot. It is the heaviest canary, so the fleet caps concurrency,
// isolates each run with a timeout, and recycles workers.
//
// Two drivers implement the same Script→Result contract behind the Driver
// interface: an HTTP-transaction driver (Go-native, the default — real per-request
// waterfall, no rendering) and a Playwright/CDP browser worker (full DOM/paint +
// PNG screenshots; shipped under browser-worker/ and run as a separate fleet).
package browser

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Action is one transaction step's verb. The same vocabulary drives both the HTTP
// driver (Field/URL/Status) and the browser driver (Selector); each uses the
// fields it needs.
type Action string

const (
	// Goto navigates to a URL (the first Goto may rely on the script's StartURL).
	Goto Action = "goto"
	// Fill sets a form field (HTTP: Field name; browser: Selector) to Value.
	Fill Action = "fill"
	// Click activates an element (browser: Selector).
	Click Action = "click"
	// Submit submits the accumulated form (HTTP: POST to URL or the form action;
	// browser: Selector of the submit control / form).
	Submit Action = "submit"
	// WaitText waits for Value text to appear (and asserts it).
	WaitText Action = "wait_text"
	// AssertText asserts Value text is present in the current page/response.
	AssertText Action = "assert_text"
	// AssertStatus asserts the last response status equals Status.
	AssertStatus Action = "assert_status"
	// Screenshot captures the current page (always captured on failure regardless).
	Screenshot Action = "screenshot"
)

var validActions = map[Action]bool{
	Goto: true, Fill: true, Click: true, Submit: true,
	WaitText: true, AssertText: true, AssertStatus: true, Screenshot: true,
}

const maxSteps = 100

// Step is one action in a transaction.
type Step struct {
	Name     string `json:"name,omitempty"`
	Action   Action `json:"action"`
	URL      string `json:"url,omitempty"`      // goto / submit target
	Selector string `json:"selector,omitempty"` // browser element selector
	Field    string `json:"field,omitempty"`    // HTTP form field name (fill)
	Value    string `json:"value,omitempty"`    // fill value / asserted text
	Status   int    `json:"status,omitempty"`   // assert_status expected code
	Optional bool   `json:"optional,omitempty"` // a failure here doesn't fail the run
}

// Script is a named multi-step transaction.
type Script struct {
	Name     string `json:"name"`
	StartURL string `json:"start_url,omitempty"`
	Steps    []Step `json:"steps"`
}

// Parse reads + validates a transaction script (JSON).
func Parse(b []byte) (Script, error) {
	var s Script
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&s); err != nil {
		return Script{}, fmt.Errorf("browser: parse script: %w", err)
	}
	if err := s.Validate(); err != nil {
		return Script{}, err
	}
	return s, nil
}

// Validate checks the script is well-formed: a name, at least one step, and the
// per-action required fields.
func (s Script) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("browser: script name is required")
	}
	if len(s.Steps) == 0 {
		return fmt.Errorf("browser: script %q has no steps", s.Name)
	}
	if len(s.Steps) > maxSteps {
		return fmt.Errorf("browser: script %q has too many steps (max %d)", s.Name, maxSteps)
	}
	for i, st := range s.Steps {
		if !validActions[st.Action] {
			return fmt.Errorf("browser: step %d: unknown action %q", i, st.Action)
		}
		if err := st.validate(s.StartURL != "" || i > 0); err != nil {
			return fmt.Errorf("browser: step %d (%s): %w", i, st.Action, err)
		}
	}
	return nil
}

// validate checks one step's required fields. hasNav is true when a navigation
// target is already established (StartURL set, or not the first step).
func (st Step) validate(hasNav bool) error {
	switch st.Action {
	case Goto:
		if st.URL == "" && !hasNav {
			return fmt.Errorf("goto needs a url (or a script start_url)")
		}
	case Fill:
		if st.Field == "" && st.Selector == "" {
			return fmt.Errorf("fill needs a field or selector")
		}
	case AssertText, WaitText:
		if st.Value == "" {
			return fmt.Errorf("%s needs a value (the expected text)", st.Action)
		}
	case AssertStatus:
		if st.Status < 100 || st.Status > 599 {
			return fmt.Errorf("assert_status needs a status in 100..599")
		}
	case Click, Submit, Screenshot:
		// no strictly-required fields
	}
	return nil
}
