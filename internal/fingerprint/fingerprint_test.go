// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package fingerprint

import (
	"slices"
	"strconv"
	"strings"
	"testing"
)

func TestMurmur3KnownVectors(t *testing.T) {
	// Published MurmurHash3 x86_32 vectors (seed 0 unless shown).
	cases := []struct {
		in   string
		seed uint32
		want uint32
	}{
		{"", 0, 0},
		{"", 1, 0x514E28B7},
		{"hello", 0, 0x248BFA47},
		{"The quick brown fox jumps over the lazy dog", 0, 0x2E4FF723},
		{"aaaa", 0x9747b28c, 0x5A97808A},
		{"abc", 0, 0xB3DD93FA},
	}
	for _, c := range cases {
		if got := murmur3(c.in, c.seed); got != c.want {
			t.Errorf("murmur3(%q, %#x) = %#x, want %#x", c.in, c.seed, got, c.want)
		}
	}
}

func TestFaviconHashMatchesTheShodanConvention(t *testing.T) {
	// mmh3.hash(base64.encodebytes(b"hello")) = mmh3.hash("aGVsbG8=\n").
	if got, want := FaviconHash([]byte("hello")), strconv.FormatInt(int64(int32(murmur3("aGVsbG8=\n", 0))), 10); got != want {
		t.Errorf("FaviconHash = %s, want %s", got, want)
	}

	// Long icons are wrapped at 76 characters, each line ending in \n.
	icon := []byte(strings.Repeat("x", 100))
	h := FaviconHash(icon)
	if h == "" || h == FaviconHash(icon[:99]) {
		t.Errorf("hash of a wrapped icon = %q", h)
	}
	if FaviconHash(nil) != "" {
		t.Error("an empty icon was hashed")
	}
}

func TestPageTitle(t *testing.T) {
	page := "<html><head><TITLE lang=en>\n  Colgate &amp; Alumni\n\tPortal </TITLE></head></html>"
	if got := PageTitle(page); got != "Colgate & Alumni Portal" {
		t.Errorf("title = %q", got)
	}
	if got := PageTitle("<html><body>no title</body></html>"); got != "" {
		t.Errorf("title = %q", got)
	}
}

func TestAnalyticsIDs(t *testing.T) {
	page := `<script async src="https://www.googletagmanager.com/gtag/js?id=G-ABC123DEF4"></script>
<script>gtag('config', 'G-ABC123DEF4'); gtag('config', 'AW-123456789');</script>
<script>(function(w,d,s,l,i){})(window,document,'script','dataLayer','GTM-K9X2ZQ');</script>
<script>ga('create', 'UA-1234567-2', 'auto');</script>
<ins class="adsbygoogle" data-ad-client="ca-pub-1234567890123456"></ins>
<script>fbq('init', '123456789012345');</script>
<script>(function(h,o,t,j,a,r){h._hjSettings={hjid:1234567,hjsv:6};})</script>
<script src="https://www.clarity.ms/tag/abcd1234ef"></script>
<p>Order G-ABCDEF123 is not an analytics ID.</p>`

	want := []string{"UA-1234567-2", "GTM-K9X2ZQ", "G-ABC123DEF4", "AW-123456789", "ca-pub-1234567890123456",
		"fb-pixel:123456789012345", "hotjar:1234567", "clarity:abcd1234ef"}
	if got := AnalyticsIDs(page); !slices.Equal(got, want) {
		t.Errorf("ids = %v\nwant  %v", got, want)
	}
}

func TestBodyHashSkipsShortBodies(t *testing.T) {
	if BodyHash("<html>moved</html>") != "" {
		t.Error("a short body was hashed")
	}

	long := strings.Repeat("<p>Colgate University alumni news</p>\n", 20)
	if a, b := BodyHash(long), BodyHash("\r\n"+strings.ReplaceAll(long, "\n", "\r\n")+"  "); a == "" || a != b {
		t.Errorf("normalized hashes differ: %q, %q", a, b)
	}
}

func TestFromHTTP(t *testing.T) {
	body := "<html><head><title>Alumni</title></head><body>" + strings.Repeat("x", 600) +
		"<script>ga('create','UA-1234567-1')</script></body></html>"
	var names []string
	for _, f := range FromHTTP(nil, body) {
		names = append(names, f.Name+"="+f.Value[:min(len(f.Value), 12)])
	}

	want := []string{"http_title=Alumni", "analytics_id=UA-1234567-1"}
	if len(names) != 3 || !slices.Equal(names[:2], want) || !strings.HasPrefix(names[2], "body_sha256=") {
		t.Errorf("fingerprints = %v", names)
	}
}
