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

func TestSecretsCommands(t *testing.T) {
	db := &secrets.FakeDB{}
	OpenStore = func(_, _ string, key *secrets.Key) (*secrets.Store, func(), error) {
		return secrets.Open(db, key), func() {}, nil
	}

	var keyOut bytes.Buffer
	if err := Run(nil, &keyOut, &bytes.Buffer{}, []string{"new-key"}, nil); err != nil {
		t.Fatal(err)
	}
	key := strings.TrimSpace(keyOut.String())
	env := map[string]string{secrets.KeyEnv: key, "USER": "tester"}
	lookup := func(n string) (string, bool) { v, ok := env[n]; return v, ok }

	run := func(in string, args ...string) (string, error) {
		var out bytes.Buffer
		err := Run(strings.NewReader(in), &out, &bytes.Buffer{}, args, lookup)
		return out.String(), err
	}

	if _, err := run("k1\n", "set", "Shodan", "apikey"); err != nil {
		t.Fatal(err)
	}
	if _, err := run("", "set", "Shodan", "secret"); err == nil {
		t.Fatal("an empty value was stored")
	}
	if _, err := run("p\n", "set", "-dir", "x", "Censys", "password"); err != nil {
		t.Fatal(err)
	}

	out, err := run("", "list")
	if err != nil || !strings.Contains(out, "Shodan") || !strings.Contains(out, "amass secrets (tester)") ||
		strings.Contains(out, "k1") {
		t.Fatalf("list = %q, %v", out, err)
	}

	next, _ := secrets.NewKey()
	if out, err = run(next+"\n", "rotate"); err != nil || !strings.Contains(out, "Rotated 2") {
		t.Fatalf("rotate = %q, %v", out, err)
	}
	if _, err := run(next+"\n", "list"); err != nil {
		t.Fatal(err)
	}
	env[secrets.KeyEnv] = next
	if _, err := run(next+"\n", "rotate"); err == nil {
		t.Fatal("rotated to the current key")
	}

	if out, err = run("", "delete", "Censys"); err != nil || !strings.Contains(out, "Censys/password") {
		t.Fatalf("delete = %q, %v", out, err)
	}
	if _, err := run("", "delete", "Censys"); err == nil {
		t.Fatal("deleted a source with nothing stored")
	}

	// flags may also come before the command, as the Compose service gives them
	if out, err = run("x\n", "-config", "c.yaml", "set", "Netlas", "apikey"); err != nil ||
		!strings.Contains(out, "Netlas/apikey") {
		t.Fatalf("set after flags = %q, %v", out, err)
	}

	delete(env, secrets.KeyEnv)
	if _, err := run("", "list"); err == nil || !strings.Contains(err.Error(), secrets.KeyEnv) {
		t.Fatalf("list without a key = %v", err)
	}
	if _, err := run("", "bogus"); err == nil {
		t.Fatal("an unknown command ran")
	}
}
