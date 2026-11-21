// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import (
	"strings"
	"testing"
)

func TestBucketProvidersCatalog(t *testing.T) {
	ps := BucketProviders()
	if len(ps) == 0 {
		t.Fatal("no bucket providers loaded")
	}

	for _, p := range ps {
		if p.Key == "" || p.Organization == "" || p.Endpoint == "" || len(p.Patterns) == 0 {
			t.Errorf("provider %q is incomplete: %+v", p.Key, p)
		}
		if !strings.HasPrefix(p.Source, "https://") {
			t.Errorf("provider %q cites no https source", p.Key)
		}
		if len(p.NotFound.Status) == 0 && len(p.NotFound.BodyContains) == 0 {
			t.Errorf("provider %q has no not_found signature", p.Key)
		}
	}
}

func TestMatchBucketHost(t *testing.T) {
	cases := []struct {
		host, wantKey, wantName string
	}{
		{"my-bucket.s3.amazonaws.com", "aws_s3", "my-bucket"},
		{"my-bucket.s3.us-east-1.amazonaws.com", "aws_s3", "my-bucket"},
		{"my-bucket.s3-us-west-2.amazonaws.com", "aws_s3", "my-bucket"},
		{"assets.s3-website-us-east-1.amazonaws.com", "aws_s3", "assets"},
		{"data.storage.googleapis.com", "gcs", "data"},
		{"acct1.blob.core.windows.net", "azure_blob", "acct1"},
		{"www.colgate.edu", "", ""},
		{"example.com", "", ""},
	}

	for _, c := range cases {
		p, name, ok := MatchBucketHost(c.host)
		if c.wantKey == "" {
			if ok {
				t.Errorf("%s unexpectedly matched provider %q (name %q)", c.host, p.Key, name)
			}
			continue
		}
		if !ok || p.Key != c.wantKey || name != c.wantName {
			t.Errorf("MatchBucketHost(%q) = %q/%q/%v, want %s/%s", c.host, p.Key, name, ok, c.wantKey, c.wantName)
		}
	}
}
