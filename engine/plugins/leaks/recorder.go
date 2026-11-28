// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package leaks

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/secrets"
	"github.com/owasp-amass/amass/v5/internal/secretscan"
	dbt "github.com/owasp-amass/asset-db/types"
	"github.com/owasp-amass/open-asset-model/general"
)

// Recorder stores the credentials and identifiers a text discloses, linked
// by discloses from the asset the text came from. This plugin records what
// the enumeration stored; a plugin that reads content the database does not
// keep, such as a document's text, records it with its own Recorder as it
// reads it.
type Recorder struct {
	name   string
	source *et.Source
	// vault returns the session database's secrets store, or nil when no
	// master key is set.
	vault func(et.Session) *secrets.Store

	mu    sync.Mutex
	key   *secrets.Key
	keyed bool
}

// NewRecorder returns a Recorder that stores finds under the plugin name
// and source given.
func NewRecorder(name string, source *et.Source) *Recorder {
	r := &Recorder{name: name, source: source}
	r.vault = r.store
	return r
}

// store opens the session database's secrets store under the master key
// from the environment, loaded once.
func (r *Recorder) store(sess et.Session) *secrets.Store {
	r.mu.Lock()
	if !r.keyed {
		r.keyed = true
		if k, err := secrets.LoadKey(os.LookupEnv); err == nil {
			r.key = k
		}
	}
	key := r.key
	r.mu.Unlock()
	if key == nil {
		return nil
	}
	return secrets.Open(sess.DB(), key)
}

// Record stores what text discloses, linked from the asset from. An
// identifier is stored in full; a secret as an exposed_secret Identifier
// with its kind and masked preview, its value sealed in the secrets store.
func (r *Recorder) Record(e *et.Event, from *dbt.Entity, text string) {
	finds := secretscan.Scan(text)
	if len(finds) == 0 || from == nil {
		return
	}
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	defer cancel()

	var vault *secrets.Store
	for _, f := range finds {
		if !f.Secret() {
			id := r.disclose(ctx, e, from, &general.Identifier{UniqueID: f.IDType + ":" + f.Value, ID: f.Value,
				Type: f.IDType})
			if f.IDType == general.AWSAccessKeyID {
				r.accountOf(ctx, e, id, f.Value)
			}
			continue
		}

		id := r.disclose(ctx, e, from, &general.Identifier{UniqueID: general.ExposedSecret + ":" + f.Kind + ":" +
			f.Hash, ID: f.Kind + ":" + f.Hash, Type: general.ExposedSecret})
		if id == nil {
			continue
		}
		support.AddProperty(ctx, e.Session, id, PropSecretKind, f.Kind)
		support.AddProperty(ctx, e.Session, id, PropSecretPreview, f.Preview)
		if vault == nil {
			vault = r.vault(e.Session)
		}
		if vault != nil {
			_ = vault.PutFound(f.Kind, f.Hash, f.Value, r.name)
		}
		e.Session.Log().Info("exposed credential found", "kind", f.Kind, "preview", f.Preview,
			"in", from.Asset.Key(), slog.Group("plugin", "name", r.name))
	}
}

// disclose stores an Identifier the asset from discloses.
func (r *Recorder) disclose(ctx context.Context, e *et.Event, from *dbt.Entity, id *general.Identifier) *dbt.Entity {
	return support.LinkAsset(ctx, e.Session, from, "discloses", id, r.source)
}

// accountOf links an AWS access key ID to the account it carries.
func (r *Recorder) accountOf(ctx context.Context, e *et.Event, keyID *dbt.Entity, value string) {
	if keyID == nil {
		return
	}
	if acct := secretscan.AWSAccountFromKeyID(value); acct != "" {
		_ = support.LinkAsset(ctx, e.Session, keyID, "cloud_account", &general.Identifier{
			UniqueID: general.AWSAccountID + ":" + acct, ID: acct, Type: general.AWSAccountID}, r.source)
	}
}
