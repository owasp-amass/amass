// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/asset-db/repository"
	dbt "github.com/owasp-amass/asset-db/types"
)

// Fields are the credential fields a data source may have.
var Fields = []string{"apikey", "secret", "username", "password"}

// DB is the Asset Database's secret store (asset-db
// repository.SecretStore), which holds only ciphertext.
type DB interface {
	PutSecret(ctx context.Context, s *dbt.Secret) (*dbt.Secret, error)
	GetSecret(ctx context.Context, name string) (*dbt.Secret, error)
	ListSecrets(ctx context.Context) ([]*dbt.Secret, error)
	DeleteSecret(ctx context.Context, name string) error
}

// Store keeps data source credentials in the Asset Database, encrypted
// under the master key. Every change is recorded, without its value, in the
// journal's secrets topic.
type Store struct {
	DB  DB
	Key *Key
	// Audit, when set, records who changed which secret and when.
	Audit *coord.Topic
}

// Entry describes a stored secret without its value.
type Entry struct {
	Source    string    `json:"source"`
	Field     string    `json:"field"`
	KeyID     string    `json:"key_id"`
	UpdatedAt time.Time `json:"updated_at"`
	UpdatedBy string    `json:"updated_by,omitempty"`
}

// timeout bounds one database call.
const timeout = time.Minute

// Open is repo's secret store under key, or nil when the database keeps no
// secrets (asset-db keeps them in PostgreSQL and SQLite) or there is no key.
func Open(repo repository.Repository, key *Key) *Store {
	db, ok := repo.(DB)
	if !ok || db == nil || key == nil {
		return nil
	}
	return &Store{DB: db, Key: key, Audit: coord.Open(repo, "secrets")}
}

// Name is the secret's name for a data source's field: "<source>/<field>",
// the source as given and the field in lower case.
func Name(source, field string) string {
	return strings.TrimSpace(source) + "/" + strings.ToLower(strings.TrimSpace(field))
}

// splitName parses a secret's name.
func splitName(name string) (source, field string, ok bool) {
	i := strings.LastIndexByte(name, '/')
	if i <= 0 || i == len(name)-1 {
		return "", "", false
	}
	return name[:i], name[i+1:], true
}

func validField(field string) bool {
	for _, f := range Fields {
		if f == field {
			return true
		}
	}
	return false
}

// Put stores a data source field's value, encrypted, replacing an earlier
// one; actor names who set it.
func (s *Store) Put(source, field, value, actor string) error {
	field = strings.ToLower(strings.TrimSpace(field))
	if strings.TrimSpace(source) == "" || strings.ContainsAny(source, "/\n\r") {
		return errors.New("invalid data source name")
	}
	if !validField(field) {
		return fmt.Errorf("a credential field is one of %s", strings.Join(Fields, ", "))
	}
	if value == "" {
		return errors.New("no value to store")
	}

	name := Name(source, field)
	ct, nonce, err := s.Key.seal(name, []byte(value))
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if _, err := s.DB.PutSecret(ctx, &dbt.Secret{Name: name, Ciphertext: ct, Nonce: nonce, KeyID: s.Key.ID(),
		UpdatedBy: actor}); err != nil {
		return err
	}
	s.audit("put", name, actor)
	return nil
}

// Delete removes a data source field's value.
func (s *Store) Delete(source, field, actor string) error {
	name := Name(source, field)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := s.DB.DeleteSecret(ctx, name); err != nil {
		return err
	}
	s.audit("delete", name, actor)
	return nil
}

// List describes the stored secrets, by source and field, never their
// values.
func (s *Store) List() ([]Entry, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	all, err := s.DB.ListSecrets(ctx)
	if err != nil {
		return nil, err
	}

	out := make([]Entry, 0, len(all))
	for _, sec := range all {
		if source, field, ok := splitName(sec.Name); ok {
			out = append(out, Entry{Source: source, Field: field, KeyID: sec.KeyID, UpdatedAt: sec.UpdatedAt,
				UpdatedBy: sec.UpdatedBy})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if !strings.EqualFold(out[i].Source, out[j].Source) {
			return strings.ToLower(out[i].Source) < strings.ToLower(out[j].Source)
		}
		return out[i].Field < out[j].Field
	})
	return out, nil
}

// Values decrypts every secret the key opens, by source and field. A
// secret under another key, or that does not open, is left out and
// counted in skipped.
func (s *Store) Values() (values map[string]map[string]string, skipped int, err error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	all, err := s.DB.ListSecrets(ctx)
	if err != nil {
		return nil, 0, err
	}

	values = map[string]map[string]string{}
	for _, sec := range all {
		source, field, ok := splitName(sec.Name)
		if !ok || sec.KeyID != s.Key.ID() {
			skipped++
			continue
		}
		plain, err := s.Key.open(sec.Name, sec.Ciphertext, sec.Nonce)
		if err != nil {
			skipped++
			continue
		}
		if values[source] == nil {
			values[source] = map[string]string{}
		}
		values[source][field] = string(plain)
	}
	return values, skipped, nil
}

// Rotate re-encrypts every secret the current key opens under next, and
// returns how many; a secret it cannot open is left as it is and counted in
// skipped. Give every engine and tool the new key afterwards.
func (s *Store) Rotate(next *Key, actor string) (rotated, skipped int, err error) {
	values, skipped, err := s.Values()
	if err != nil {
		return 0, skipped, err
	}
	to := &Store{DB: s.DB, Key: next, Audit: s.Audit}
	for source, fields := range values {
		for field, value := range fields {
			if err := to.Put(source, field, value, actor); err != nil {
				return rotated, skipped, err
			}
			rotated++
		}
	}
	return rotated, skipped, nil
}

// audit records a change, without its value.
func (s *Store) audit(action, name, actor string) {
	if s.Audit != nil {
		_, _ = s.Audit.Append(action, name, map[string]string{"name": name, "actor": actor, "key_id": s.Key.ID()})
	}
}
