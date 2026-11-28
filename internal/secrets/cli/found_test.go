// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/secrets"
)

// amass secrets found prints a found credential's value under the key, and
// refuses a reference that is not an exposed_secret ID.
func TestFoundCommand(t *testing.T) {
	db := &secrets.FakeDB{}
	OpenStore = func(_, _ string, key *secrets.Key) (*secrets.Store, func(), error) {
		return secrets.Open(db, key), func() {}, nil
	}
	enc, _ := secrets.NewKey()
	key, _ := secrets.ParseKey(enc)
	if err := secrets.Open(db, key).PutFound("github_token", "abc123", "found-value", "test"); err != nil {
		t.Fatal(err)
	}
	lookup := func(n string) (string, bool) {
		if n == secrets.KeyEnv {
			return enc, true
		}
		return "", false
	}

	var out bytes.Buffer
	if err := Run(nil, &out, &bytes.Buffer{}, []string{"found", "exposed_secret:github_token:abc123"},
		lookup); err != nil || strings.TrimSpace(out.String()) != "found-value" {
		t.Fatalf("found = %q, %v", out.String(), err)
	}
	if err := Run(nil, &bytes.Buffer{}, &bytes.Buffer{}, []string{"found", "nohash"}, lookup); err == nil {
		t.Error("a malformed reference was accepted")
	}
	if err := Run(nil, &bytes.Buffer{}, &bytes.Buffer{}, []string{"found", "github_token:missing"},
		lookup); err == nil {
		t.Error("a credential with no kept value was printed")
	}
}
