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
// pattern matched "mailto:webmaster@hamilton.edu" and bare addresses, and
// prefixing them with http:// stored fake URLs whose username was the mailbox.
func TestExtractURLsSkipsEmailsAndOtherSchemes(t *testing.T) {
	body := `<a href="mailto:webmaster@hamilton.edu">email</a> collegeevents@hamilton.edu
		<a href="tel:+13158594011">call</a> <a href="https://www.hamilton.edu/library">library</a>
		lib.hamilton.edu:3000/images/x.jpg medium.com/@hamilton http://ocsp.digicert.com`

	var got []string
	for _, u := range ExtractURLsFromString(body) {
		got = append(got, u.Raw)
	}
	want := []string{
		"https://www.hamilton.edu/library",
		"http://lib.hamilton.edu:3000/images/x.jpg",
		"http://medium.com/@hamilton",
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
	got := ExtractEmailsFromString(`mailto:WebMaster@Hamilton.edu, collegeevents@hamilton.edu.
		again webmaster@hamilton.edu and not-an-email@ or @hamilton.edu`)
	want := []string{"webmaster@hamilton.edu", "collegeevents@hamilton.edu"}
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
