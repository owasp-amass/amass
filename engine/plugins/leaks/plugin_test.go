// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package leaks

import (
	"context"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/secrets"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/platform"
	oamurl "github.com/owasp-amass/open-asset-model/url"
)

// fakeToken is a token-shaped value that is not anyone's.
const fakeToken = "ghp_Q7mZ2pX9vB4kL8nR3tW6yC1dF5gH0jSQ7mZ2"

func targets(t *testing.T, sess *plugintest.Session, from *dbt.Entity, label string) []*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	edges, err := sess.DB().OutgoingEdges(ctx, from, time.Time{}, label)
	if err != nil {
		return nil
	}
	var out []*dbt.Entity
	for _, edge := range edges {
		if a, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
			out = append(out, a)
		}
	}
	return out
}

func newTestLeaks(t *testing.T) (*leaks, *secrets.Store) {
	t.Helper()
	enc, err := secrets.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	key, err := secrets.ParseKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	vault := &secrets.Store{DB: &secrets.FakeDB{}, Key: key}
	l := NewLeaks().(*leaks)
	l.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	l.vault = func(et.Session) *secrets.Store { return vault }
	return l, vault
}

// A URL's token becomes an exposed_secret Identifier with its kind and
// preview, sealed in the vault; its AWS access key ID is kept in full with
// the account it carries.
func TestURLDisclosures(t *testing.T) {
	sess := plugintest.NewSession(t)
	l, vault := newTestLeaks(t)
	raw := "https://files.example.com/a.zip?X-Amz-Credential=ASIAY34FZKBOKMUTVV7A%2F20261128%2Fus-east-1&token=" +
		fakeToken
	u := sess.Asset(t, &oamurl.URL{Raw: raw, Scheme: "https", Host: "files.example.com", Path: "/a.zip"})
	if err := l.checkURL(&et.Event{Entity: u, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}

	var secret, keyID *dbt.Entity
	found := targets(t, sess, u, "discloses")
	for _, ent := range found {
		switch ent.Asset.(*general.Identifier).Type {
		case general.ExposedSecret:
			secret = ent
		case general.AWSAccessKeyID:
			keyID = ent
		}
	}
	if secret == nil || keyID == nil {
		t.Fatalf("disclosures of %s are incomplete: %d found", raw, len(found))
	}
	id := secret.Asset.(*general.Identifier)
	if strings.Contains(id.UniqueID, fakeToken) || !strings.HasPrefix(id.ID, "github_token:") {
		t.Errorf("the secret identifier = %+v", id)
	}
	hash := strings.TrimPrefix(id.ID, "github_token:")
	if v, err := vault.Found("github_token", hash, "test"); err != nil || v != fakeToken {
		t.Errorf("the sealed value = %q, %v", v, err)
	}
	if accts := targets(t, sess, keyID, "cloud_account"); len(accts) != 1 ||
		accts[0].Asset.(*general.Identifier).ID != "609629065308" {
		t.Errorf("the key's account = %v", accts)
	}
}

// A banner or header with nothing in it records nothing.
func TestServiceWithoutDisclosures(t *testing.T) {
	sess := plugintest.NewSession(t)
	l, _ := newTestLeaks(t)
	s := sess.Asset(t, &platform.Service{ID: "www.example.com:tcp:443-0123456789abcdef", Type: "http",
		Output: "HTTP/1.1 200 OK", Attributes: map[string][]string{"Server": {"nginx"}}})
	if err := l.checkService(&et.Event{Entity: s, Session: sess, Dispatcher: &plugintest.Dispatcher{}}); err != nil {
		t.Fatal(err)
	}
	if got := targets(t, sess, s, "discloses"); len(got) != 0 {
		t.Errorf("disclosures = %v", got)
	}
}
