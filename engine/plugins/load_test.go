// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"io"
	"log/slog"
	"testing"

	"github.com/owasp-amass/amass/v5/engine/registry"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

// handlerErrors keeps the errors from registering handlers.
type handlerErrors struct {
	et.Registry
	errs []error
}

func (r *handlerErrors) RegisterHandler(h *et.Handler) error {
	err := r.Registry.RegisterHandler(h)
	if err != nil {
		r.errs = append(r.errs, err)
	}

	return err
}

// Every plugin's handlers register together: two exclusive handlers at one
// position for an asset type, or one handler name registered twice, stops
// the engine at startup. Plugins that fail to start for other reasons, such
// as no network in the test, are not this test's concern.
func TestPluginHandlersRegisterTogether(t *testing.T) {
	r := &handlerErrors{Registry: registry.NewRegistry(slog.New(slog.NewTextHandler(io.Discard, nil)))}

	for _, f := range pluginNewFuncs {
		if p := f(); p != nil {
			if err := p.Start(r); err == nil {
				defer p.Stop()
			}
		}
	}
	for _, err := range r.errs {
		t.Errorf("a handler did not register: %v", err)
	}
}
