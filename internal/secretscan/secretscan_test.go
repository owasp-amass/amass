// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package secretscan

import (
	"strings"
	"testing"
)

// fakeToken builds a token-shaped value that is not anyone's: a prefix and a
// fixed high-entropy body.
func fakeToken(prefix string, n int) string {
	const body = "Q7mZ2pX9vB4kL8nR3tW6yC1dF5gH0jS"
	var b strings.Builder
	b.WriteString(prefix)
	for b.Len() < len(prefix)+n {
		b.WriteString(body)
	}
	return b.String()[:len(prefix)+n]
}

func TestScanFindsSecretsAndIdentifiers(t *testing.T) {
	gh := fakeToken("ghp_", 36)
	text := "config: token=" + gh + "\nkey ASIAY34FZKBOKMUTVV7A role arn:aws:iam::609629065308:role/app " +
		"and the docs key AKIAIOSFODNN7EXAMPLE, slack xoxb-xxxxxxxxxxxxxxxx"
	finds := Scan(text)
	kinds := map[string]Find{}
	for _, f := range finds {
		kinds[f.Kind] = f
	}
	if len(finds) != 3 {
		t.Fatalf("finds = %+v", finds)
	}
	g := kinds["github_token"]
	if !g.Secret() || g.Value != gh || g.Preview != gh[:4]+"…"+gh[len(gh)-4:] || len(g.Hash) != 64 {
		t.Errorf("GitHub token = %+v", g)
	}
	if k := kinds["aws_access_key_id"]; k.Secret() || k.Preview != "ASIAY34FZKBOKMUTVV7A" {
		t.Errorf("access key ID = %+v", k)
	}
	if a := kinds["aws_account_id"]; a.Value != "609629065308" || a.IDType != "aws_account_id" {
		t.Errorf("ARN account = %+v", a)
	}
}

func TestMask(t *testing.T) {
	gh := fakeToken("ghp_", 36)
	got := Mask("use " + gh + " with ASIAY34FZKBOKMUTVV7A")
	if strings.Contains(got, gh) || !strings.Contains(got, "[github_token "+gh[:4]+"…") ||
		!strings.Contains(got, "ASIAY34FZKBOKMUTVV7A") {
		t.Errorf("Mask = %q", got)
	}
	if Mask("nothing here") != "nothing here" {
		t.Error("text without secrets changed")
	}
}

func TestPrivateKeyPreview(t *testing.T) {
	body := strings.Repeat(fakeToken("", 31)+"\n", 4)
	key := "-----BEGIN RSA PRIVATE KEY-----\n" + body + "-----END RSA PRIVATE KEY-----"
	finds := Scan("x " + key + " y")
	if len(finds) != 1 || finds[0].Kind != "private_key" || strings.Contains(finds[0].Preview, body) {
		t.Fatalf("finds = %+v", finds)
	}
}

// The public test vector of the access key ID decoding.
func TestAWSAccountFromKeyID(t *testing.T) {
	if got := AWSAccountFromKeyID("ASIAY34FZKBOKMUTVV7A"); got != "609629065308" {
		t.Errorf("account = %q", got)
	}
	if AWSAccountFromKeyID("AKIA123") != "" || AWSAccountFromKeyID("ghp_ASIAY34FZKBOKMUTVV7") != "" {
		t.Error("a non-key decoded")
	}
}

func TestEveryPatternLoads(t *testing.T) {
	if len(loadCatalog().Patterns) < 5 {
		t.Fatal("too few patterns")
	}
}
