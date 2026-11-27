// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"strconv"
	"strings"
	"testing"
)

func TestFQDNFilterInsert(t *testing.T) {
	ff := NewFQDNFilter()
	defer ff.Close()

	fqdn := "www.cs.utica.edu"
	ff.Insert(fqdn)

	cur := ff
	labels := strings.Split(fqdn, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if _, found := cur[labels[i]]; !found {
			t.Errorf("Passive DNS Filter Insert failed for label %s at index %d", labels[i], i)
			break
		}
		if i > 0 {
			cur = cur[labels[i]].(FQDNFilter)
		}
	}
}

func TestFQDNFilterPrune(t *testing.T) {
	ff := NewFQDNFilter()
	defer ff.Close()

	limit := 50
	for i := 0; i < limit; i++ {
		fqdn := "www" + strconv.Itoa(i) + ".cs.utica.edu"
		ff.Insert(fqdn)
	}

	var found bool
	var name string
	ff.Prune(limit)
	for _, fqdn := range ff.Slice() {
		if fqdn == "www1.cs.utica.edu" {
			name = fqdn
			found = true
			break
		}
	}

	if found {
		t.Errorf("Passive DNS Filter Prune failed to remove the labels: %s", name)
	}
}

func TestFQDNFilterSlice(t *testing.T) {
	ff := NewFQDNFilter()
	defer ff.Close()

	fqdn := "www.cs.utica.edu"
	ff.Insert(fqdn)

	if fqdn != ff.Slice()[0] {
		t.Errorf("Passive DNS Filter Slice failed to produce the expected FQDN: %s", fqdn)
	}
}

func TestKeyIDString(t *testing.T) {
	if got := KeyIDString([]byte{0x00, 0xab, 0x0f, 0xff}); got != "00:AB:0F:FF" {
		t.Errorf("KeyIDString = %q", got)
	}
	if got := KeyIDString(nil); got != "" {
		t.Errorf("KeyIDString(nil) = %q", got)
	}
}

// Email addresses and non-web schemes in a page are not URLs: the relaxed
// pattern matched "mailto:webmaster@owasp.org" and bare addresses, and
// prefixing them with http:// stored fake URLs whose username was the mailbox.
func TestExtractURLsSkipsEmailsAndOtherSchemes(t *testing.T) {
	body := `<a href="mailto:webmaster@owasp.org">email</a> collegeevents@owasp.org
		<a href="tel:+13155554011">call</a> <a href="https://www.owasp.org/library">library</a>
		lib.owasp.org:3000/images/x.jpg medium.com/@owasp http://ocsp.digicert.com`

	var got []string
	for _, u := range ExtractURLsFromString(body) {
		got = append(got, u.Raw)
	}
	want := []string{
		"https://www.owasp.org/library",
		"http://lib.owasp.org:3000/images/x.jpg",
		"http://medium.com/@owasp",
		"http://ocsp.digicert.com",
	}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("URLs = %v, want %v", got, want)
	}
	for _, u := range ExtractURLsFromString(body) {
		if u.Username != "" || u.Password != "" {
			t.Errorf("a URL carries a mailbox as credentials: %s", u.Raw)
		}
	}

	if u := ExtractURLFromString("contact: mailto:a@b.edu then https://b.edu/x"); u == nil ||
		u.Raw != "https://b.edu/x" {
		t.Errorf("ExtractURLFromString = %v", u)
	}
}

func TestExtractEmailsFromString(t *testing.T) {
	got := ExtractEmailsFromString(`mailto:WebMaster@OWASP.org, collegeevents@owasp.org.
		again webmaster@owasp.org and not-an-email@ or @owasp.org`)
	want := []string{"webmaster@owasp.org", "collegeevents@owasp.org"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Errorf("emails = %v, want %v", got, want)
	}
}

// A link read from HTML is stored unescaped: "&amp;" between query
// parameters is "&" in the URL.
func TestExtractURLsUnescapesHTML(t *testing.T) {
	body := `<a href="http://ezproxy.example.edu/login?url=https://search.example.com/x?a=1&amp;b=2&amp;c=3">db</a>`

	urls := ExtractURLsFromString(body)
	if len(urls) != 1 {
		t.Fatalf("URLs = %v", urls)
	}
	if got := urls[0].Raw; strings.Contains(got, "&amp;") || !strings.Contains(got, "a=1&b=2&c=3") {
		t.Errorf("URL %q, want the query unescaped", got)
	}
}

// A URL in an HTTP Link header, plain or HTML-escaped, ends at the bracket
// that closes it: the header's "<…>; rel=shortlink" adds no ">" or ";" to it.
func TestExtractURLsFromLinkHeaders(t *testing.T) {
	for _, banner := range []string{
		`link: <https://www.owasp.org/?p=177853>; rel=shortlink`,
		`link: &lt;https://www.owasp.org/?p=177853&gt;; rel=shortlink`,
		`link: &lt;https://www.owasp.org/?p=177853&gt; rel=shortlink`,
	} {
		urls := ExtractURLsFromString(banner)
		if len(urls) != 1 || urls[0].Raw != "https://www.owasp.org/?p=177853" {
			var got []string
			for _, u := range urls {
				got = append(got, u.Raw)
			}
			t.Errorf("%q gave %q, want only https://www.owasp.org/?p=177853", banner, got)
		}
	}
}

// Funding sources give exchange dates as timestamps, dates, months or years;
// all become RFC 3339, which the Asset Database requires, and an unknown form
// is kept as given.
func TestTransferDate(t *testing.T) {
	for in, want := range map[string]string{
		"2009-09-18":            "2009-09-18T00:00:00Z",
		"09/18/2009":            "2009-09-18T00:00:00Z",
		"2009-09":               "2009-09-01T00:00:00Z",
		"2019":                  "2019-01-01T00:00:00Z",
		" 2021-03-04T05:06:07Z": "2021-03-04T05:06:07Z",
		"2021-03-04 05:06:07":   "2021-03-04T05:06:07Z",
		"2024-03-01+01:00":      "2024-03-01T00:00:00Z",
		"2024-03-01-05:00":      "2024-03-01T00:00:00Z",
		"FY2019":                "FY2019",
	} {
		if got := TransferDate(in); got != want {
			t.Errorf("TransferDate(%q) = %q, want %q", in, got, want)
		}
	}
}

// A link read from a document is a web URL only when it is one: mailto: and
// tel: links are not, and a link ends at an unescaped quote. A capture holding
// what a URL escapes is malformed.
func TestWebURLAndMalformedURL(t *testing.T) {
	if u := WebURL(" https://www.example.edu/apply "); u == nil || u.Raw != "https://www.example.edu/apply" {
		t.Errorf("WebURL kept %v", u)
	}
	for _, raw := range []string{"mailto:help@example.edu?subject='To", "tel:+13155550100", "help@example.edu"} {
		if u := WebURL(raw); u != nil {
			t.Errorf("WebURL(%q) = %v, want none", raw, u.Raw)
		}
	}
	if u := WebURL("https://www.example.edu/x?subject='To"); u == nil || strings.Contains(u.Raw, "'") {
		t.Errorf("WebURL did not end the link at the quote: %v", u)
	}
	for raw, want := range map[string]bool{
		"https://www.example.edu/x?subject='To": true, "https://www.example.edu/a b": true,
		"https://www.example.edu/<x>": true, "https://www.example.edu/x?q=%27a%27&p=1": false,
		"https://www.example.edu/apply": false,
	} {
		if got := MalformedURL(raw); got != want {
			t.Errorf("MalformedURL(%q) = %v, want %v", raw, got, want)
		}
	}
}
