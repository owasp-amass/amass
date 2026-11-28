// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import "github.com/owasp-amass/amass/v5/internal/secretscan"

// Masked returns history with every credential in its text replaced by the
// credential's kind and masked preview, so a found key never reaches a
// model, local or hosted. Identifiers, such as AWS account IDs, stay whole.
// The history passed in is left as it was.
func Masked(history []Message) []Message {
	var out []Message
	for i, m := range history {
		masked := secretscan.Mask(m.Text)
		if masked == m.Text {
			continue
		}
		if out == nil {
			out = append([]Message(nil), history...)
		}
		out[i].Text = masked
	}
	if out == nil {
		return history
	}
	return out
}
