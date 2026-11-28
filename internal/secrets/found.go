// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"context"
	"errors"
	"strings"
)

// foundPrefix starts the name of a credential found exposed in collected
// content, kept so its owner can get the value back: "found:<kind>:<hash>",
// the kind and SHA-256 of an exposed_secret Identifier. Found credentials
// are never data source credentials.
const foundPrefix = "found:"

// ParseFound reads a found credential's reference: an exposed_secret
// Identifier's ID ("<kind>:<hash>") or unique ID
// ("exposed_secret:<kind>:<hash>").
func ParseFound(ref string) (kind, hash string, ok bool) {
	ref = strings.TrimPrefix(strings.TrimSpace(ref), "exposed_secret:")
	kind, hash, ok = strings.Cut(ref, ":")
	if !ok || kind == "" || hash == "" || strings.ContainsAny(hash, ":/") {
		return "", "", false
	}
	return kind, hash, true
}

// FoundName is the secret's name for a found credential.
func FoundName(kind, hash string) string { return foundPrefix + kind + ":" + hash }

// isFound reports whether a secret's name is a found credential's.
func isFound(name string) bool { return strings.HasPrefix(name, foundPrefix) }

// PutFound seals the value of a credential found exposed; actor names what
// found it. The value is stored only encrypted, and never logged.
func (s *Store) PutFound(kind, hash, value, actor string) error {
	if kind == "" || hash == "" || strings.ContainsAny(kind+hash, ":/\n\r") || value == "" {
		return errors.New("a found credential needs a kind, a hash and a value")
	}
	return s.put(FoundName(kind, hash), value, actor)
}

// Found opens the value of a found credential; actor names who asked, and
// the read is recorded, without the value.
func (s *Store) Found(kind, hash, actor string) (string, error) {
	name := FoundName(kind, hash)
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	sec, err := s.DB.GetSecret(ctx, name)
	if err != nil {
		return "", err
	}
	if sec == nil {
		return "", errors.New("no value is kept for this credential")
	}
	if sec.KeyID != s.Key.ID() {
		return "", errors.New("the credential is sealed under another master key")
	}
	plain, err := s.Key.open(name, sec.Ciphertext, sec.Nonce)
	if err != nil {
		return "", err
	}
	s.audit("read", name, actor)
	return string(plain), nil
}
