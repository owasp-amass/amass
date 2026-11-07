// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"testing"
)

func TestNewURLScan(t *testing.T) {
	p := NewURLScan()
	if p == nil {
		t.Fatal("NewURLScan returned nil")
	}

	if p.Name() != "URLScan" {
		t.Errorf("expected plugin name 'URLScan', got %s", p.Name())
	}

	u, ok := p.(*urlScan)
	if !ok {
		t.Fatal("failed to cast plugin to *urlScan")
	}

	if u.source == nil {
		t.Fatal("expected source to be initialized")
	}

	if u.source.Name != "URLScan" {
		t.Errorf("expected source name 'URLScan', got %s", u.source.Name)
	}

	if u.source.Confidence != 80 {
		t.Errorf("expected confidence 80, got %d", u.source.Confidence)
	}

	if u.rlimit == nil {
		t.Error("expected rate limiter to be initialized")
	}
}
