// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package bucket

import (
	"testing"

	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	"github.com/owasp-amass/amass/v5/internal/semantics"
)

func TestClassify(t *testing.T) {
	prov := semantics.BucketProvider{
		NotFound:      semantics.BucketSignature{Status: []int{404}, BodyContains: []string{"NoSuchBucket"}},
		PublicListing: semantics.BucketSignature{Status: []int{200}, BodyContains: []string{"<ListBucketResult"}},
	}

	cases := []struct {
		code int
		body string
		want string
	}{
		{404, "<Error><Code>NoSuchBucket</Code></Error>", "absent"},
		{200, "<ListBucketResult xmlns=\"...\"><Contents></Contents></ListBucketResult>", "public"},
		{403, "<Error><Code>AccessDenied</Code></Error>", "exists"},
		{200, "<html>a normal page</html>", "exists"},
		{301, "", "exists"},
		{500, "server error", ""},
		{404, "some other 404 body", ""},
	}

	for _, c := range cases {
		got := classify(prov, &amasshttp.Response{StatusCode: c.code, Body: c.body})
		if got != c.want {
			t.Errorf("classify(code=%d, body=%q) = %q, want %q", c.code, c.body, got, c.want)
		}
	}
}

func TestClassifyUsesRealCatalog(t *testing.T) {
	// Every provider in the catalog should classify its own documented
	// not-found body as absent.
	for _, prov := range semantics.BucketProviders() {
		if len(prov.NotFound.BodyContains) == 0 {
			continue
		}
		code := 404
		if len(prov.NotFound.Status) > 0 {
			code = prov.NotFound.Status[0]
		}
		resp := &amasshttp.Response{StatusCode: code, Body: prov.NotFound.BodyContains[0]}
		if got := classify(prov, resp); got != "absent" {
			t.Errorf("provider %s: classify of its not-found signature = %q, want absent", prov.Key, got)
		}
	}
}

func TestNewStorageBucketFromProbeStatus(t *testing.T) {
	var s3 semantics.BucketProvider
	for _, p := range semantics.BucketProviders() {
		if p.Key == "aws_s3" {
			s3 = p
		}
	}
	if s3.Service == "" {
		t.Fatal("the catalog has no aws_s3 provider with a service name")
	}

	cases := []struct {
		status         string
		exists, public bool
	}{
		{"public", true, true},
		{"exists", true, false},
		{"absent", false, false},
	}
	for _, c := range cases {
		b := newStorageBucket(s3, "example-assets", c.status)
		if b.ID != "s3:example-assets" || b.Name != "example-assets" || b.Service != "s3" ||
			b.Provider != "Amazon Web Services" {
			t.Errorf("%s: identity = %+v", c.status, *b)
		}
		if b.Exists != c.exists || b.Public != c.public {
			t.Errorf("%s: exists=%v public=%v, want exists=%v public=%v", c.status, b.Exists, b.Public,
				c.exists, c.public)
		}
	}
}
