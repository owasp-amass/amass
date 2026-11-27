// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package review keeps the proposals the lenses make about an Open Asset
// Model graph: the journal they are recorded in, the evidence bundles that
// justify them, automatic attribution during enumerations, rechecks of
// stored decisions and the writers that apply accepted ownership, merges,
// identity corrections and removals. A trained model may decide automatic
// attribution through OwnershipScorer, but none is needed.
package review
