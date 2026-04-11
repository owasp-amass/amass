// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package whois

import (
	"regexp"
	"strings"
	"unicode"
)

// PrivacyMatch holds details about why a value was flagged.
type PrivacyMatch struct {
	Indicator string // human-readable label for the match
	Pattern   string // pattern that matched (for debugging/telemetry)
}

// PrivacyDetection is the result of analyzing a single WHOIS field value.
type PrivacyDetection struct {
	IsPlaceholder bool
	Score         int            // higher = more confident placeholder/redaction/privacy proxy
	Matches       []PrivacyMatch // which indicators triggered
	Normalized    string         // normalized value inspected
}

// DetectRegistrantPlaceholder analyzes a WHOIS registrant field value and detects
// whether it looks like a privacy/redaction placeholder or privacy-proxy service.
//
// Typical usage: call this for each registrant field (name/org/email/address/phone).
func DetectRegistrantPlaceholder(value string) PrivacyDetection {
	n := normalizeWHOISValue(value)
	if n == "" {
		return PrivacyDetection{
			IsPlaceholder: false,
			Score:         0,
			Matches:       nil,
			Normalized:    n,
		}
	}

	// fast-path: if the value is basically "n/a", "redacted", etc.
	// (These are strong signals for placeholders.)
	var (
		score   int
		matches []PrivacyMatch
	)

	add := func(points int, indicator, pattern string) {
		score += points
		matches = append(matches, PrivacyMatch{
			Indicator: indicator,
			Pattern:   pattern,
		})
	}

	// high-confidence exact-ish tokens
	// note: normalization already lowercases and squashes whitespace/punct
	strongTokens := map[string]string{
		"redacted for privacy":         "REDACTED_FOR_PRIVACY",
		"redacted":                     "REDACTED",
		"data protected":               "DATA_PROTECTED",
		"data protected not disclosed": "DATA_PROTECTED_NOT_DISCLOSED",
		"not disclosed":                "NOT_DISCLOSED",
		"not available":                "NOT_AVAILABLE",
		"private registration":         "PRIVATE_REGISTRATION",
		"privacy protected":            "PRIVACY_PROTECTED",
		"privacy protection":           "PRIVACY_PROTECTION",
		"privacy customer":             "PRIVACY_CUSTOMER",
		"gdpr masked":                  "GDPR_MASKED",
		"masked for privacy":           "MASKED_FOR_PRIVACY",
		"withheld for privacy":         "WITHHELD_FOR_PRIVACY",
		"contact the registrar":        "CONTACT_REGISTRAR",
		"contact registrar":            "CONTACT_REGISTRAR",
		"registration private":         "REGISTRATION_PRIVATE",
		"whois privacy":                "WHOIS_PRIVACY",
		"whoisguard":                   "WHOISGUARD",
		"domains by proxy":             "DOMAINS_BY_PROXY",
		"contact privacy inc":          "CONTACT_PRIVACY_INC",
		"privacy service provided by":  "PRIVACY_SERVICE_PROVIDED_BY",
		"whois privacy service":        "WHOIS_PRIVACY_SERVICE",
		"whoisprotectservice":          "WHOIS_PROTECT_SERVICE",
		"perfect privacy llc":          "PERFECT_PRIVACY",
		"privacyguardian org":          "PRIVACY_GUARDIAN",
		"privacy protection service":   "PRIVACY_PROTECTION_SERVICE",
		"domain privacy service":       "DOMAIN_PRIVACY_SERVICE",
		"identity protected":           "IDENTITY_PROTECTED",
	}

	for token, label := range strongTokens {
		if strings.Contains(n, token) {
			// strong tokens get high weight
			add(10, label, token)
		}
	}

	// regex patterns for registrar boilerplate / common redaction formats.
	// these are intentionally broad but anchored by "privacy/redacted/proxy" terms
	regexes := []struct {
		re        *regexp.Regexp
		points    int
		indicator string
		pattern   string
	}{
		{
			re:        regexp.MustCompile(`\bredacted\b.*\bprivacy\b`),
			points:    12,
			indicator: "REDACTED_PRIVACY_PHRASE",
			pattern:   `\bredacted\b.*\bprivacy\b`,
		},
		{
			re:        regexp.MustCompile(`\b(privac|proxy|protect)\w*\b.*\bservice\b`),
			points:    8,
			indicator: "PRIVACY_PROXY_SERVICE_PHRASE",
			pattern:   `\b(privac|proxy|protect)\w*\b.*\bservice\b`,
		},
		{
			re:        regexp.MustCompile(`\b(gdpr)\b.*\b(redact|mask|withhold)\w*\b`),
			points:    10,
			indicator: "GDPR_REDACTION_PHRASE",
			pattern:   `\b(gdpr)\b.*\b(redact|mask|withhold)\w*\b`,
		},
		{
			re:        regexp.MustCompile(`\b(whois)\b.*\b(privacy|protected|guard)\b`),
			points:    8,
			indicator: "WHOIS_PRIVACY_PHRASE",
			pattern:   `\b(whois)\b.*\b(privacy|protected|guard)\b`,
		},
		{
			re:        regexp.MustCompile(`\b(contact)\b.*\b(privacy|proxy)\b`),
			points:    8,
			indicator: "CONTACT_PRIVACY_PROXY_PHRASE",
			pattern:   `\b(contact)\b.*\b(privacy|proxy)\b`,
		},
		{
			re:        regexp.MustCompile(`\b(privacy)\b.*\b(please|use|via|through)\b.*\b(form|email|web)\b`),
			points:    6,
			indicator: "PRIVACY_CONTACT_FORM_BOILERPLATE",
			pattern:   `\b(privacy)\b.*\b(please|use|via|through)\b.*\b(form|email|web)\b`,
		},
		// common "N/A" / "na" / "-" placeholders as whole-value matches
		{
			re:        regexp.MustCompile(`^(n\s*/\s*a|na|none|null|unknown|[-–—]+)$`),
			points:    4,
			indicator: "GENERIC_EMPTY_PLACEHOLDER",
			pattern:   `^(n\s*/\s*a|na|none|null|unknown|[-–—]+)$`,
		},
	}

	for _, r := range regexes {
		if r.re.MatchString(n) {
			add(r.points, r.indicator, r.pattern)
		}
	}

	// heuristic: email-like redactions (e.g., "redacted@privacy", "email hidden", etc.)
	if looksLikeEmailRedaction(n) {
		add(7, "EMAIL_REDACTED_HEURISTIC", "looksLikeEmailRedaction")
	}

	// heuristic: phone redaction patterns (e.g., "+1.0000000000", "000-000-0000")
	if looksLikePhonePlaceholder(n) {
		add(5, "PHONE_PLACEHOLDER_HEURISTIC", "looksLikePhonePlaceholder")
	}

	isPlaceholder := score >= 10
	return PrivacyDetection{
		IsPlaceholder: isPlaceholder,
		Score:         score,
		Matches:       matches,
		Normalized:    n,
	}
}

func normalizeWHOISValue(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}

	// lowercase and collapse to a canonical token stream:
	// - convert punctuation to spaces
	// - collapse multiple spaces
	// - keep ascii letters/digits; allow some unicode letters/digits too
	var b strings.Builder
	b.Grow(len(s))

	prevSpace := false
	for _, r := range strings.ToLower(s) {
		switch {
		case unicode.IsLetter(r) || unicode.IsDigit(r):
			b.WriteRune(r)
			prevSpace = false
		case r == '@' || r == '.' || r == '+' || r == '-' || r == '_' || r == '/':
			// keep common email/phone/url-ish characters to help heuristics,
			// but treat most punctuation as space
			b.WriteRune(r)
			prevSpace = false
		default:
			if !prevSpace {
				b.WriteByte(' ')
				prevSpace = true
			}
		}
	}

	out := strings.TrimSpace(b.String())
	// collapse whitespace to single spaces
	out = strings.Join(strings.Fields(out), " ")
	return out
}

func looksLikeEmailRedaction(n string) bool {
	// common phrases
	if strings.Contains(n, "email hidden") ||
		strings.Contains(n, "email redacted") ||
		strings.Contains(n, "redacted email") ||
		strings.Contains(n, "email withheld") {
		return true
	}

	// "redacted@redacted" / "privacy@privacy" / "masked@masked"
	// very common in privacy-proxy outputs
	emailLike := regexp.MustCompile(`\b(redacted|privacy|masked|protected|withheld)\b[^ ]*@[^ ]*\b(redacted|privacy|masked|protected|withheld)\b`)
	if emailLike.MatchString(n) {
		return true
	}

	// generic "xxxxx@xxxxx" style
	xMask := regexp.MustCompile(`\b[x\*]{3,}@\b[x\*]{3,}\b`)
	return xMask.MatchString(n)
}

func looksLikePhonePlaceholder(n string) bool {
	// all zeros / repeated digits in common phone formats
	zeroish := regexp.MustCompile(`\b(\+?\d{1,3}[-. ]?)?(0{3,}[-. ]?){2,}\b`)
	if zeroish.MatchString(n) {
		return true
	}

	// explicit placeholder words
	if strings.Contains(n, "phone hidden") ||
		strings.Contains(n, "phone redacted") ||
		strings.Contains(n, "number withheld") ||
		strings.Contains(n, "withheld") && strings.Contains(n, "phone") {
		return true
	}
	return false
}
