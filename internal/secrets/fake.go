// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"sort"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/internal/coord"
	dbt "github.com/owasp-amass/asset-db/types"
)

// FakeDB keeps secrets and the journal in memory, as the Asset Database
// does, for tests; Open takes it as a database.
type FakeDB struct {
	coord.FakeStore
	mu      sync.Mutex
	secrets map[string]dbt.Secret
}

// PutSecret implements DB.
func (f *FakeDB) PutSecret(_ context.Context, s *dbt.Secret) (*dbt.Secret, error) {
	if err := s.Validate(); err != nil {
		return nil, err
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.secrets == nil {
		f.secrets = map[string]dbt.Secret{}
	}
	c := *s
	c.UpdatedAt = time.Now()
	f.secrets[s.Name] = c
	return &c, nil
}

// GetSecret implements DB.
func (f *FakeDB) GetSecret(_ context.Context, name string) (*dbt.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	s, ok := f.secrets[name]
	if !ok {
		return nil, errors.New("secret not found")
	}
	return &s, nil
}

// ListSecrets implements DB.
func (f *FakeDB) ListSecrets(context.Context) ([]*dbt.Secret, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	out := make([]*dbt.Secret, 0, len(f.secrets))
	for _, s := range f.secrets {
		c := s
		out = append(out, &c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out, nil
}

// DeleteSecret implements DB.
func (f *FakeDB) DeleteSecret(_ context.Context, name string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	delete(f.secrets, name)
	return nil
}
