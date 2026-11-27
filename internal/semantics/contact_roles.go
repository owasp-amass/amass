// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package semantics

import "slices"

// OwnContactLabels are the relations by which an asset names a contact
// record of its own: a domain's registrant, administrative, technical and
// billing contacts, a web page's or account's contact details and a
// certificate's subject.
var OwnContactLabels = []string{"registrant_contact", "admin_contact", "technical_contact", "billing_contact",
	"contact", "subject_contact"}

// ThirdPartyContactLabels are the relations by which an asset names another
// party's contact record: a domain's registrar, a network's abuse desk and a
// certificate's issuer. Their details belong to that party, not to the
// asset's owner.
var ThirdPartyContactLabels = []string{"registrar_contact", "abuse_contact", "issuer_contact"}

// ThirdPartyContact reports whether every label by which a contact record is
// named is a third party's (ThirdPartyContactLabels). A record named by no
// label is not.
func ThirdPartyContact(labels []string) bool {
	if len(labels) == 0 {
		return false
	}
	for _, l := range labels {
		if !slices.Contains(ThirdPartyContactLabels, l) {
			return false
		}
	}
	return true
}
