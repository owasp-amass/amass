// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package lens

import (
	"net/netip"
	"slices"
	"testing"
)

func TestCAAAccountURI(t *testing.T) {
	for in, want := range map[string]string{
		`0 issue "letsencrypt.org; accounturi=https://acme-v02.api.letsencrypt.org/acme/acct/111"`: "https://acme-v02.api.letsencrypt.org/acme/acct/111",
		`0 issuewild "pki.goog; accounturi=urn:x:1; validationmethods=dns-01"`:                     "urn:x:1",
		`0 issue "letsencrypt.org"`:                      "",
		`0 iodef "mailto:security@owasp.org"`:            "",
		`0 issue "letsencrypt.org; validationmethods=a"`: "",
		`garbage`: "",
	} {
		if got := caaAccountURI(in); got != want {
			t.Errorf("caaAccountURI(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCommonPrivateAddress(t *testing.T) {
	ignore := []netip.Prefix{netip.MustParsePrefix("192.168.0.0/23")}
	for in, want := range map[string]bool{
		"10.20.30.40":  false,
		"10.20.30.1":   true,
		"10.20.30.254": true,
		"192.168.1.77": true,
		"192.168.2.77": false,
		"fd00::5":      false,
	} {
		if got := commonPrivateAddress(netip.MustParseAddr(in), ignore); got != want {
			t.Errorf("commonPrivateAddress(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestReservedAddress(t *testing.T) {
	for in, want := range map[string]bool{
		"10.1.2.3": true, "172.16.5.4": true, "192.168.1.1": true, "100.64.1.1": true, "127.0.0.1": true,
		"169.254.1.1": true, "fd00::1": true, "8.8.8.8": false, "2001:4860::8888": false,
	} {
		if got := reservedAddress(netip.MustParseAddr(in)); got != want {
			t.Errorf("reservedAddress(%s) = %v, want %v", in, got, want)
		}
	}
}

func TestPageNamesOrganizationText(t *testing.T) {
	cases := []struct {
		page, name string
		want       bool
	}{
		{`<footer>&copy; 2025 <a href="/">Utica University</a></footer>`, "Utica University", true},
		{`<p>Copyright 2019-2025, the Utica University. All rights reserved.</p>`, "Utica University", true},
		{`<p>(c) Utica University</p>`, "Utica University", true},
		{`<p>Utica University announced a new dean.</p><footer>© 2025 Example News</footer>`, "Utica University", false},
		{`<script type="application/ld+json">{"@context":"https://schema.org","@type":"CollegeOrUniversity",` +
			`"name":"Utica University","url":"https://www.utica.edu"}</script>`, "Utica University", true},
		{`<script type="application/ld+json">{"@type":"NewsArticle","about":{"name":"Utica University"}}</script>`,
			"Utica University", false},
		{`<footer>© 2025 Utica Universityville</footer>`, "Utica University", false},
	}
	for _, c := range cases {
		if got := pageNamesOrganization(c.page, c.name) != ""; got != c.want {
			t.Errorf("pageNamesOrganization(%q) = %v, want %v", c.page, got, c.want)
		}
	}
}

func TestBucketHosts(t *testing.T) {
	page := `<img src="https://utica-media.s3.amazonaws.com/a.png"><img src="//utica-media.s3.amazonaws.com/b.png">` +
		`<a href="https://s3.amazonaws.com/">S3</a><a href="https://www.utica.edu/">home</a>` +
		`<link href="https://uticastore.blob.core.windows.net/css/site.css">`
	got := bucketHosts(page)
	if !slices.Contains(got, "utica-media.s3.amazonaws.com") || slices.Contains(got, "s3.amazonaws.com") ||
		slices.Contains(got, "www.utica.edu") {
		t.Errorf("bucketHosts = %v", got)
	}
	if n := len(slices.DeleteFunc(slices.Clone(got), func(h string) bool { return h != "utica-media.s3.amazonaws.com" })); n != 1 {
		t.Errorf("a host repeated on the page was listed %d times", n)
	}
}

func TestProviderManagedName(t *testing.T) {
	for in, want := range map[string]bool{
		"sni.cloudflaressl.com": true, "*.cloudflaressl.com": true, "imperva.com": true, "x.incapsula.com": true,
		"www.utica.edu": false, "notcloudflaressl.com": false,
	} {
		if got := ProviderManagedName(in); got != want {
			t.Errorf("ProviderManagedName(%q) = %v, want %v", in, got, want)
		}
	}
}
