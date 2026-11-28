// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"slices"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/graph/graphtest"
)

// secretsGraph answers the value search for exposed_secret Identifiers.
type secretsGraph struct {
	graphtest.FakeGraph
}

func (g secretsGraph) FindByAttribute(_ context.Context, assetType, key, value string, _ bool,
	_ int) ([]graph.Asset, bool, error) {
	var out []graph.Asset
	for _, a := range g.Assets {
		if a.Type == assetType && graph.ContentString(a, key) == value {
			out = append(out, a)
		}
	}
	return out, false, nil
}

func (secretsGraph) FindByTagValue(context.Context, string, string, string, bool, int) ([]graph.Asset, bool,
	error) {
	return nil, false, nil
}

// Only credentials the footprint discloses are noted, with the masked
// preview and the AWS account of the access key ID found beside the key.
func TestLeakedCredentials(t *testing.T) {
	ident := func(id, typ, value string) graph.Asset {
		return graph.Asset{ID: id, Type: "Identifier", Key: typ + ":" + value,
			Content: map[string]any{"id": value, "id_type": typ}}
	}
	prop := func(name, value string) graph.Evidence {
		return graph.Evidence{Kind: "property", Property: map[string]any{"property_name": name, "property_value": value}}
	}
	page := graph.Asset{ID: "u1", Type: "URL", Key: "https://www.example.com/config.js",
		Content: map[string]any{"url": "https://www.example.com/config.js"}}
	elsewhere := graph.Asset{ID: "u2", Type: "URL", Key: "https://www.example.net/app.js",
		Content: map[string]any{"url": "https://www.example.net/app.js"}}
	awsKey := ident("s1", exposedSecretType, "aws_secret_access_key:h1")
	token := ident("s2", exposedSecretType, "github_token:h2")
	keyID := ident("k1", accessKeyIDType, "AKIAIOSFODNN7EXAMPLE")
	acct := ident("a1", "aws_account_id", "111122223333")

	g := secretsGraph{graphtest.FakeGraph{
		Assets: map[string]graph.Asset{"u1": page, "u2": elsewhere, "s1": awsKey, "s2": token, "k1": keyID,
			"a1": acct},
		Links: []graph.Relation{
			{ID: "e1", FromID: "u1", ToID: "s1", Label: "discloses"},
			{ID: "e2", FromID: "u1", ToID: "k1", Label: "discloses"},
			{ID: "e3", FromID: "k1", ToID: "a1", Label: "cloud_account"},
			{ID: "e4", FromID: "u2", ToID: "s2", Label: "discloses"},
		},
		EvidenceByID: map[string][]graph.Evidence{
			"s1": {prop(secretKindProp, "aws_secret_access_key"), prop(secretPreviewProp, "wJal…KEY")},
			"s2": {prop(secretKindProp, "github_token"), prop(secretPreviewProp, "ghp_…0jS")},
		},
	}}

	var got []string
	if err := leakedCredentials(context.Background(), g, map[string]graph.Asset{"u1": page},
		func(example string) { got = append(got, example) }); err != nil {
		t.Fatal(err)
	}
	want := []string{"aws_secret_access_key wJal…KEY in https://www.example.com/config.js (AWS account 111122223333) " +
		"[exposed_secret:aws_secret_access_key:h1]"}
	if !slices.Equal(got, want) {
		t.Errorf("leaked = %q, want %q", got, want)
	}
}
