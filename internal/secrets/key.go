// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package secrets keeps the credentials the tools sharing an Asset Database
// use, such as data source API keys, encrypted in the database under a
// master key every engine and tool is given, and resolves a session's
// credentials through a chain of providers: the datasources file, the
// environment, then the database.
package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"strings"
)

// The environment variables that give the master key: the key itself
// (base64 of 32 bytes), or a file that holds it.
const (
	KeyEnv     = "AMASS_SECRETS_KEY"
	KeyFileEnv = "AMASS_SECRETS_KEY_FILE"
)

// Key is the master key secrets are encrypted under (AES-256-GCM). Its ID,
// stored with each secret, tells which key encrypted it, so a key can be
// rotated.
type Key struct {
	id   string
	aead cipher.AEAD
}

// NewKey returns a new random master key, base64-encoded, to give every
// engine and tool in KeyEnv.
func NewKey() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.StdEncoding.EncodeToString(b), nil
}

// ParseKey reads a base64-encoded 32-byte master key.
func ParseKey(encoded string) (*Key, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(encoded))
	if err != nil || len(raw) != 32 {
		return nil, errors.New("a secrets key is 32 bytes, base64-encoded")
	}
	block, err := aes.NewCipher(raw)
	if err != nil {
		return nil, err
	}
	aead, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	sum := sha256.Sum256(raw)
	return &Key{id: hex.EncodeToString(sum[:8]), aead: aead}, nil
}

// LoadKey reads the master key from KeyEnv or the file KeyFileEnv names, or
// returns nil (and no error) when neither is set: then the database store
// is off and credentials come from the other providers.
func LoadKey(lookup func(string) (string, bool)) (*Key, error) {
	if v, ok := lookup(KeyEnv); ok && strings.TrimSpace(v) != "" {
		return ParseKey(v)
	}
	if path, ok := lookup(KeyFileEnv); ok && strings.TrimSpace(path) != "" {
		data, err := os.ReadFile(strings.TrimSpace(path))
		if err != nil {
			return nil, fmt.Errorf("read the secrets key file: %w", err)
		}
		return ParseKey(string(data))
	}
	return nil, nil
}

// ID names the key without revealing it.
func (k *Key) ID() string { return k.id }

// seal encrypts value for the secret named name; the name is authenticated
// with it, so a ciphertext moved to another name does not open.
func (k *Key) seal(name string, value []byte) (ciphertext, nonce []byte, err error) {
	nonce = make([]byte, k.aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, err
	}
	return k.aead.Seal(nil, nonce, value, []byte(name)), nonce, nil
}

// open decrypts the secret named name.
func (k *Key) open(name string, ciphertext, nonce []byte) ([]byte, error) {
	if len(nonce) != k.aead.NonceSize() {
		return nil, errors.New("the secret's nonce is malformed")
	}
	return k.aead.Open(nil, nonce, ciphertext, []byte(name))
}
