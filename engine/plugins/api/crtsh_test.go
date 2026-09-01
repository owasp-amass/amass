// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
)

func TestNewCrtsh(t *testing.T) {
	p := NewCrtsh()
	if p == nil {
		t.Fatal("NewCrtsh returned nil")
	}

	if p.Name() != "crt.sh" {
		t.Errorf("expected plugin name 'crt.sh', got %s", p.Name())
	}

	c, ok := p.(*crtsh)
	if !ok {
		t.Fatal("failed to cast plugin to *crtsh")
	}

	if c.source == nil {
		t.Fatal("expected source to be initialized")
	}

	if c.source.Name != "crt.sh" {
		t.Errorf("expected source name 'crt.sh', got %s", c.source.Name)
	}

	if c.source.Confidence != 100 {
		t.Errorf("expected confidence 100, got %d", c.source.Confidence)
	}

	if c.rlimit == nil {
		t.Error("expected rate limiter to be initialized")
	}
}
