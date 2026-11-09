// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import "strings"

const codeFence = "\x60\x60\x60"

// ModelJSON returns the JSON payload of a structured model reply. It removes
// only packaging that models commonly add around an otherwise bare JSON
// value: a leading <think>...</think> reasoning block (Qwen3 and other
// reasoning models served through OpenAI-compatible endpoints) and one
// enclosing Markdown code fence, with or without a language tag. It never
// extracts JSON from surrounding prose; callers still decode strictly and
// reject anything else.
func ModelJSON(raw string) string {
	s := strings.TrimSpace(raw)
	if strings.HasPrefix(s, "<think>") {
		if end := strings.Index(s, "</think>"); end >= 0 {
			s = strings.TrimSpace(s[end+len("</think>"):])
		}
	}
	if strings.HasPrefix(s, codeFence) {
		// A missing closing fence (a truncated reply) is tolerated, as before.
		s = strings.TrimSuffix(strings.TrimPrefix(s, codeFence), codeFence)
		// Drop an optional language tag on the opening fence line.
		if nl := strings.IndexByte(s, '\n'); nl >= 0 {
			tag := strings.TrimSpace(s[:nl])
			if tag == "" || isFenceTag(tag) {
				s = s[nl+1:]
			}
		} else {
			for _, tag := range []string{"json", "JSON"} {
				s = strings.TrimPrefix(s, tag)
			}
		}

		s = strings.TrimSpace(s)
	}

	return s
}

func isFenceTag(tag string) bool {
	for _, r := range tag {
		if (r < 'a' || r > 'z') && (r < 'A' || r > 'Z') {
			return false
		}
	}

	return true
}
