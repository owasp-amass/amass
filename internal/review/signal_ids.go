// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"
)

// signalIDRenames maps the ownership signal IDs used before the two signal
// catalogs became one (internal/semantics/signals.json, 2026-11-25) to the
// merged catalog's. The horizontal signal IDs did not change.
var signalIDRenames = map[string]string{
	"shared_registrant_details":      "shared-registrant-details",
	"shared_registrant_email_domain": "shared-registrant-email-domain",
	"dkim_key_reuse":                 "dkim-key-reuse",
	"txt_verification_token":         "txt-verification-token",
	"certificate_key_reuse":          "certificate-key-reuse",
	"certificate_public_key_reuse":   "certificate-public-key-reuse",
	"private_ca_issuance":            "private-ca-issuance",
	"security_txt_reference":         "security-txt-reference",
	"bug_bounty_scope":               "bug-bounty-scope",
	"roa_authorizes_own_asn":         "roa-authorizes-own-asn",
	"self_hosted_dns":                "self-hosted-dns",
	"email_auth_reference":           "spf-authorizes",
	"hosting_in_footprint":           "hosting-in-footprint",
	"certificate_colisting":          "certificate-colisting",
	"web_redirect_to_organization":   "web-redirect-to-organization",
	"reverse_dns_in_namespace":       "reverse-dns-in-namespace",
	"dns_provider_unique_set":        "dns-provider-delegation-set",
	"shared_nameserver_set":          "shared-nameserver-set",
	"tls_fingerprint_match":          "tls-fingerprint-match",
	"name_token":                     "name-token",
	"document_operator":              "document-operator",
	"parked_for_sale":                "parked-for-sale",
	"shared_analytics_id":            "shared-analytics-id",
	"same_favicon":                   "shared-favicon",
	"same_page_content":              "shared-page-content",
	"same_page_title":                "shared-page-title",
	"ssh_host_key_reuse":             "ssh-host-key-reuse",
	"caa_account_binding":            "caa-account-binding",
	"shared_private_addresses":       "shared-private-addresses",
	"mark_certificate_identifier":    "mark-certificate-identifier",
	"security_txt_shared_key":        "security-txt-shared-key",
	"page_names_organization":        "page-names-organization",
	"page_references_bucket":         "page-references-bucket",
}

// MigrateSignalIDs rewrites the journal's records with the merged signal
// catalog's IDs: every "signal" value and every "signal_ids" entry that names
// an old ID. The journal as it was is kept beside it, named with the time
// (review.jsonl.bak-20261125T190000Z). A journal with nothing to change is
// left as it is. It returns how many records changed.
func (j *Journal) MigrateSignalIDs() (int, error) {
	if j == nil || j.Path == "" {
		return 0, errors.New("journal path required")
	}
	if j.Shared() {
		// a shared journal is only appended to; its records are imported
		// from a file journal already migrated (ImportJournal)
		return 0, nil
	}

	j.mu.Lock()
	defer j.mu.Unlock()
	old, err := os.ReadFile(j.Path)
	if errors.Is(err, os.ErrNotExist) {
		return 0, nil
	} else if err != nil {
		return 0, err
	}

	var out bytes.Buffer
	changed := 0
	sc := bufio.NewScanner(bytes.NewReader(old))
	sc.Buffer(make([]byte, 64*1024), 64<<20)
	for sc.Scan() {
		line := sc.Bytes()
		if n, ok := renameSignals(line); ok {
			out.Write(n)
			changed++
		} else {
			out.Write(line)
		}
		out.WriteByte('\n')
	}
	if err := sc.Err(); err != nil {
		return 0, err
	}
	if changed == 0 {
		return 0, nil
	}

	backup := fmt.Sprintf("%s.bak-%s", j.Path, time.Now().UTC().Format("20060102T150405Z"))
	if err := os.WriteFile(backup, old, 0600); err != nil {
		return 0, err
	}
	tmp := j.Path + ".migrating"
	if err := os.WriteFile(tmp, out.Bytes(), 0600); err != nil {
		return 0, err
	}
	return changed, os.Rename(tmp, j.Path)
}

// renameSignals returns the record with its old signal IDs renamed, and
// whether anything changed. A line that is not a JSON record is kept as it is.
func renameSignals(line []byte) ([]byte, bool) {
	dec := json.NewDecoder(bytes.NewReader(line))
	dec.UseNumber()
	var rec any
	if err := dec.Decode(&rec); err != nil {
		return nil, false
	}
	if !renameIn(rec) {
		return nil, false
	}

	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	if err := enc.Encode(rec); err != nil {
		return nil, false
	}
	return bytes.TrimRight(b.Bytes(), "\n"), true
}

func renameIn(v any) bool {
	changed := false
	switch t := v.(type) {
	case map[string]any:
		for k, x := range t {
			switch {
			case k == "signal":
				if s, ok := x.(string); ok {
					if n, ok := signalIDRenames[s]; ok {
						t[k] = n
						changed = true
						continue
					}
				}
			case k == "signal_ids":
				if ids, ok := x.([]any); ok {
					for i, id := range ids {
						if s, ok := id.(string); ok {
							if n, ok := signalIDRenames[s]; ok {
								ids[i] = n
								changed = true
							}
						}
					}
					continue
				}
			}
			if renameIn(x) {
				changed = true
			}
		}
	case []any:
		for _, x := range t {
			if renameIn(x) {
				changed = true
			}
		}
	}
	return changed
}
