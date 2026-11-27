// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import "strings"

// DocumentTextProperties are the properties that hold text from collected
// documents: the findings a document model reads, which quote the document.
// The Asset Database keeps no copy of a document's content itself. Only the model the user named in
// options.ai.documents reads them, unless the user shares them with other models
// (options.ai.documents.share_with_assistants).
var DocumentTextProperties = []string{"doc_statement"}

// IsDocumentTextProperty reports whether a property name holds document text.
func IsDocumentTextProperty(name string) bool {
	for _, p := range DocumentTextProperties {
		if strings.EqualFold(name, p) {
			return true
		}
	}
	return false
}

// WithheldDocumentText is the value shown in place of withheld document text,
// naming its tag so each withheld value stays distinct and can be counted.
func WithheldDocumentText(tagID string) string {
	return "[document text withheld: " + tagID + "; see options.ai.documents.share_with_assistants]"
}
