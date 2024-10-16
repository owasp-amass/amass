// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"log/slog"
	"os"
	"testing"

	et "github.com/owasp-amass/amass/v4/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

func TestNewRegistry(t *testing.T) {
	r := NewRegistry(slog.New(slog.NewTextHandler(os.Stdout, nil)))
	if r == nil {
		t.Error("Registry is nil")
	}
}

func FakeHandler(e *et.Event) error {
	return nil
}

func TestRegisterHandler(t *testing.T) {
	r := NewRegistry(slog.New(slog.NewTextHandler(os.Stdout, nil)))

	// Register a handler
	err := r.RegisterHandler(&et.Handler{
		Name:       "Test-MainHandler",
		Transforms: []string{"Test-Transform"},
		EventType:  oam.FQDN,
		Callback:   FakeHandler,
	})
	if err != nil {
		t.Error("No handlers registered")
	}
}
