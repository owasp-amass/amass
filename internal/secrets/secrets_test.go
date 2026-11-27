// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secrets

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/owasp-amass/amass/v5/config"
)

func newKey(t *testing.T) *Key {
	t.Helper()
	enc, err := NewKey()
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParseKey(enc)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestKeySealsUnderTheName(t *testing.T) {
	k := newKey(t)
	ct, nonce, err := k.seal("Shodan/apikey", []byte("v"))
	if err != nil {
		t.Fatal(err)
	}
	if got, err := k.open("Shodan/apikey", ct, nonce); err != nil || string(got) != "v" {
		t.Fatalf("open = %q, %v", got, err)
	}
	// a ciphertext moved to another name does not open
	if _, err := k.open("Censys/apikey", ct, nonce); err == nil {
		t.Fatal("a ciphertext opened under another name")
	}
	if _, err := newKey(t).open("Shodan/apikey", ct, nonce); err == nil {
		t.Fatal("a ciphertext opened under another key")
	}
}

func TestParseAndLoadKey(t *testing.T) {
	if _, err := ParseKey("c2hvcnQ="); err == nil {
		t.Fatal("a short key was accepted")
	}
	enc, _ := NewKey()
	a, _ := ParseKey(enc)
	b, _ := ParseKey(enc + "\n")
	if a.ID() != b.ID() || len(a.ID()) != 16 {
		t.Fatalf("IDs %q and %q", a.ID(), b.ID())
	}

	none := func(string) (string, bool) { return "", false }
	if k, err := LoadKey(none); k != nil || err != nil {
		t.Fatalf("LoadKey with nothing set = %v, %v", k, err)
	}

	path := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(path, []byte(enc+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fromFile := func(n string) (string, bool) { return path, n == KeyFileEnv }
	if k, err := LoadKey(fromFile); err != nil || k.ID() != a.ID() {
		t.Fatalf("LoadKey from the file = %v, %v", k, err)
	}
	fromEnv := func(n string) (string, bool) { return enc, n == KeyEnv }
	if k, err := LoadKey(fromEnv); err != nil || k.ID() != a.ID() {
		t.Fatalf("LoadKey from the environment = %v, %v", k, err)
	}
}

func TestStore(t *testing.T) {
	db := &FakeDB{}
	k := newKey(t)
	if Open(db, nil) != nil {
		t.Fatal("a store opened without a key")
	}
	s := Open(db, k)

	if err := s.Put("Shodan", "APIKey", "k1", "tester"); err != nil {
		t.Fatal(err)
	}
	if err := s.Put("Shodan", "token", "x", "tester"); err == nil {
		t.Fatal("an unknown field was stored")
	}
	if err := s.Put("a/b", "apikey", "x", "tester"); err == nil {
		t.Fatal("a source with a slash was stored")
	}
	_ = s.Put("Censys", "username", "u", "tester")
	_ = s.Put("Censys", "password", "p", "tester")

	entries, err := s.List()
	if err != nil || len(entries) != 3 || entries[0].Source != "Censys" || entries[2].Field != "apikey" ||
		entries[2].KeyID != k.ID() {
		t.Fatalf("List = %+v, %v", entries, err)
	}

	values, skipped, err := s.Values()
	if err != nil || skipped != 0 || values["Shodan"]["apikey"] != "k1" || values["Censys"]["password"] != "p" {
		t.Fatalf("Values = %v, %d, %v", values, skipped, err)
	}
	if n := len(db.Records()); n != 3 {
		t.Fatalf("%d audit records, want 3", n)
	}
	for _, r := range db.Records() {
		if r.Topic != "secrets" {
			t.Fatalf("audit record in topic %q", r.Topic)
		}
	}

	if err := s.Delete("Censys", "password", "tester"); err != nil {
		t.Fatal(err)
	}
	if values, _, _ = s.Values(); values["Censys"]["password"] != "" {
		t.Fatal("a deleted secret remains")
	}
}

func TestRotate(t *testing.T) {
	db := &FakeDB{}
	old, next := newKey(t), newKey(t)
	s := Open(db, old)
	_ = s.Put("Shodan", "apikey", "k1", "tester")
	// a secret under a third key is left as it is
	_ = Open(db, newKey(t)).Put("Censys", "apikey", "k2", "tester")

	rotated, skipped, err := s.Rotate(next, "tester")
	if err != nil || rotated != 1 || skipped != 1 {
		t.Fatalf("Rotate = %d, %d, %v", rotated, skipped, err)
	}
	if values, _, _ := Open(db, next).Values(); values["Shodan"]["apikey"] != "k1" {
		t.Fatalf("the new key opens %v", values)
	}
	if values, _, _ := s.Values(); len(values) != 0 {
		t.Fatalf("the old key still opens %v", values)
	}
}

func TestFillPrecedence(t *testing.T) {
	db := &FakeDB{}
	s := Open(db, newKey(t))
	_ = s.Put("Shodan", "apikey", "from-store", "tester")
	_ = s.Put("Censys", "apikey", "from-store", "tester")
	_ = s.Put("VirusTotal", "apikey", "from-store", "tester")

	cfg := config.NewConfig()
	cfg.DataSrcConfigs = &config.DataSourceConfig{GlobalOptions: map[string]int{"minimum_ttl": 1440},
		Datasources: []*config.DataSource{
			{Name: "Shodan", Creds: map[string]*config.Credentials{"mine": {Apikey: "from-file"}}},
			{Name: "Censys"},
		}}
	environ := []string{"AMASS_SECRET_CENSYS_APIKEY=from-env", "AMASS_SECRET_CENSYS_TOKEN=ignored",
		"AMASS_SECRET_NETLAS_APIKEY=from-env", "OTHER=x"}

	filled, err := Fill(cfg, s, environ)
	if err != nil {
		t.Fatal(err)
	}
	if len(filled) != 3 {
		t.Fatalf("filled %v", filled)
	}

	get := func(name string) *config.Credentials { return cfg.DataSrcConfigs.GetCredentials(name) }
	if c := get("Shodan"); c.Apikey != "from-file" {
		t.Fatalf("the file lost to %q", c.Apikey)
	}
	if c := get("Censys"); c.Apikey != "from-env" {
		t.Fatalf("Censys has %q, want the environment's", c.Apikey)
	}
	if c := get("VirusTotal"); c == nil || c.Apikey != "from-store" {
		t.Fatalf("VirusTotal has %+v, want the store's", c)
	}
	if ds := cfg.GetDataSourceConfig("netlas"); ds == nil || ds.TTL != 1440 || ds.Creds[account].Apikey != "from-env" {
		t.Fatalf("netlas = %+v", ds)
	}

	sources, err := Sources(s, environ)
	if err != nil || sources["CENSYS"] != FromEnvironment || sources["VIRUSTOTAL"] != FromDatabase ||
		sources["NETLAS"] != FromEnvironment {
		t.Fatalf("Sources = %v, %v", sources, err)
	}
}
