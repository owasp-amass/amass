// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"errors"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

func TestRunHandlerRecoversPanics(t *testing.T) {
	sess := plugintest.NewSession(t)
	e := &et.Event{Name: "test", Session: sess}

	panicky := &et.Handler{Name: "Panicky-Handler", Callback: func(*et.Event) error {
		var values []string
		_ = values[0] // index out of range
		return nil
	}}
	err := runHandler(panicky, e)
	if err == nil || !strings.Contains(err.Error(), "Panicky-Handler handler panicked") ||
		!strings.Contains(err.Error(), "index out of range") {
		t.Fatalf("a panicking handler returned %v", err)
	}

	// Without a session the panic is still recovered.
	if err := runHandler(panicky, &et.Event{}); err == nil {
		t.Error("a panic without a session was not reported")
	}

	failing := &et.Handler{Name: "Failing", Callback: func(*et.Event) error { return errors.New("boom") }}
	if err := runHandler(failing, e); err == nil || err.Error() != "boom" {
		t.Errorf("a handler's own error became %v", err)
	}

	fine := &et.Handler{Name: "Fine", Callback: func(*et.Event) error { return nil }}
	if err := runHandler(fine, e); err != nil {
		t.Errorf("a successful handler returned %v", err)
	}
}
