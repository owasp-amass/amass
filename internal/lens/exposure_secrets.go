// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/secretscan"
)

// ExposureLeaked is the exposure class of credentials found in what the
// footprint serves or publishes.
const ExposureLeaked = "leaked_credentials"

// The Identifier type and properties the exposed-secrets plugin stores for a
// credential it finds (engine plugin leaks). The value itself is sealed in
// the secrets store and never read here.
const (
	exposedSecretType = "exposed_secret"
	accessKeyIDType   = "aws_access_key_id"
	secretKindProp    = "secret_kind"
	secretPreviewProp = "secret_preview"
)

// leakedCredentials notes each credential an asset of the footprint
// discloses, with its kind and masked preview, where it was found and, for
// AWS keys found beside their access key ID, the account. Credentials found
// only outside the footprint are not reported. It reads with one value
// search; a repository without value searches gives none.
func leakedCredentials(ctx context.Context, g graph.Graph, owned map[string]graph.Asset,
	note func(string)) error {
	vs, ok := g.(ValueSearcher)
	if !ok {
		return nil
	}
	found, _, err := vs.FindByAttribute(ctx, "Identifier", "id_type", exposedSecretType, false, 0)
	if errors.Is(err, ErrValueSearchUnsupported) {
		return nil
	} else if err != nil {
		return err
	}

	for _, sec := range found {
		in, err := g.Edges(ctx, sec.ID, "in", "discloses", time.Time{})
		if err != nil {
			return err
		}
		var where []graph.Asset
		for _, e := range in {
			if a, mine := owned[e.FromID]; mine {
				where = append(where, a)
			}
		}
		if len(where) == 0 {
			continue
		}

		kind, preview := secretLabel(ctx, g, sec)
		for _, a := range where {
			// Where a key was found can carry it, in a URL's query, say.
			example := fmt.Sprintf("%s %s in %s", kind, preview, secretscan.Mask(maskURL(graph.AssetLabel(a))))
			if strings.HasPrefix(kind, "aws_") {
				accounts, err := awsAccountsDisclosed(ctx, g, a.ID)
				if err != nil {
					return err
				}
				if len(accounts) > 0 {
					example += " (AWS account " + strings.Join(accounts, ", ") + ")"
				}
			}
			// The reference is what amass secrets found takes; it holds only a hash.
			note(example + " [" + exposedSecretType + ":" + graph.ContentString(sec, "id") + "]")
		}
	}
	return nil
}

// secretLabel returns a found credential's kind and masked preview, from
// its properties, or the kind its ID carries when they are missing.
func secretLabel(ctx context.Context, g graph.Graph, sec graph.Asset) (string, string) {
	kind, _, _ := strings.Cut(graph.ContentString(sec, "id"), ":")
	preview := "(masked)"
	if ev, err := g.Evidence(ctx, sec.ID, 20); err == nil {
		if v := propertyValues(ev, secretKindProp); len(v) > 0 {
			kind = v[0]
		}
		if v := propertyValues(ev, secretPreviewProp); len(v) > 0 {
			preview = v[0]
		}
	}
	return kind, preview
}

// awsAccountsDisclosed returns the AWS accounts of the access key IDs an
// asset discloses, which the plugin decodes from each key ID.
func awsAccountsDisclosed(ctx context.Context, g graph.Graph, id string) ([]string, error) {
	out, err := g.Edges(ctx, id, "out", "discloses", time.Time{})
	if err != nil {
		return nil, err
	}
	var accounts []string
	for _, e := range out {
		key, err := g.GetAsset(ctx, e.ToID)
		if err != nil || graph.ContentString(key, "id_type") != accessKeyIDType {
			continue
		}
		links, err := g.Edges(ctx, key.ID, "out", "cloud_account", time.Time{})
		if err != nil {
			return nil, err
		}
		for _, l := range links {
			if acct, err := g.GetAsset(ctx, l.ToID); err == nil {
				if v := graph.ContentString(acct, "id"); v != "" && !slices.Contains(accounts, v) {
					accounts = append(accounts, v)
				}
			}
		}
	}
	slices.Sort(accounts)
	return accounts, nil
}
