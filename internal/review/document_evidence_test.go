// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package review

import (
	"testing"

	"github.com/owasp-amass/amass/v5/internal/lens"
)

// The ownership model scores a proposal without its document evidence, so a
// document never helps an ownership edge be written automatically; the
// proposal itself keeps everything for the reviewer.
func TestWithoutDocumentEvidence(t *testing.T) {
	p := OwnershipProposal{
		Signals:   []string{"identity via shared registrant", lens.DocumentSignalKind + " via FQDN \"vpn\" is operated by"},
		SignalIDs: []string{"shared-registrant-details", "document-operator"},
	}
	q := withoutDocumentEvidence(p)
	if len(q.Signals) != 1 || q.Signals[0] != "identity via shared registrant" {
		t.Errorf("signals %v", q.Signals)
	}
	if len(q.SignalIDs) != 1 || q.SignalIDs[0] != "shared-registrant-details" {
		t.Errorf("signal IDs %v", q.SignalIDs)
	}
	if len(p.Signals) != 2 || len(p.SignalIDs) != 2 {
		t.Error("the proposal lost its document evidence")
	}
}

// A bug-bounty declaration, like a document, is left out of what the
// ownership model decides on.
func TestWithoutDeclarationEvidence(t *testing.T) {
	p := OwnershipProposal{
		Signals:   []string{"identity via shared registrant", lens.DeclarationSignalKind + " via bug-bounty program scope FQDN"},
		SignalIDs: []string{"shared-registrant-details", "bug-bounty-scope"},
	}
	q := withoutDocumentEvidence(p)
	if len(q.Signals) != 1 || len(q.SignalIDs) != 1 || q.SignalIDs[0] != "shared-registrant-details" {
		t.Errorf("signals %v, IDs %v", q.Signals, q.SignalIDs)
	}
}
