// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package graph

import "strings"

// ContributionSourcePrefix begins the source of what an assistant
// contributed with the MCP contribute tool: amass-ai:<client>.
const ContributionSourcePrefix = "amass-ai:"

// IsContributionSource reports whether a source is an assistant's
// contribution.
func IsContributionSource(source string) bool {
	return strings.HasPrefix(source, ContributionSourcePrefix)
}

// ContributionPolicy is a graph's answer to whether contributions may be
// strong evidence (options.ai.contributions.strong_evidence).
type ContributionPolicy interface {
	ContributionsStrong() bool
}

// ContributionsStrong reports whether g lets contributions be strong
// evidence. A graph without the policy does not.
func ContributionsStrong(g Graph) bool {
	p, ok := g.(ContributionPolicy)
	return ok && p.ContributionsStrong()
}
