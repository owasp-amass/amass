// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package confighelp

import (
	"strings"
	"testing"
)

const withSecrets = `scope:
  domains:
    - owasp.org
datasources:
  - name: Shodan
    ttl: 1440
    creds:
      account:
        apikey: SECRET-KEY-123
        secret: top-secret
`

func TestRedactSecrets(t *testing.T) {
	out, err := RedactSecrets(withSecrets)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out, "SECRET-KEY-123") || strings.Contains(out, "top-secret") {
		t.Errorf("a credential survived redaction:\n%s", out)
	}
	if !strings.Contains(out, redacted) {
		t.Errorf("nothing was redacted:\n%s", out)
	}
	// Non-secret settings and the credential keys are kept.
	for _, keep := range []string{"owasp.org", "Shodan", "apikey", "account"} {
		if !strings.Contains(out, keep) {
			t.Errorf("redaction dropped %q:\n%s", keep, out)
		}
	}
}

func TestRedactSecretsNoDatasources(t *testing.T) {
	in := "scope:\n  ports:\n    - 443\n"
	out, err := RedactSecrets(in)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, "443") {
		t.Errorf("a config without datasources was altered:\n%s", out)
	}

	// An empty document comes back unchanged.
	if out, err := RedactSecrets(""); err != nil || out != "" {
		t.Errorf("empty content changed: %q, %v", out, err)
	}
}

func TestContainsSecrets(t *testing.T) {
	if !ContainsSecrets(withSecrets) {
		t.Error("credentials were not detected")
	}
	if ContainsSecrets("scope:\n  ports:\n    - 443\n") {
		t.Error("a config without credentials was flagged")
	}
	// A datasources entry without creds is not a secret.
	if ContainsSecrets("datasources:\n  - name: Shodan\n    ttl: 60\n") {
		t.Error("a credential-free data source was flagged")
	}
	// An empty creds block sets nothing.
	if ContainsSecrets("datasources:\n  - name: Shodan\n    creds: {}\n") {
		t.Error("an empty creds block was flagged")
	}
}
