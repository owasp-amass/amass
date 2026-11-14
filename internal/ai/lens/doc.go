// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package lens computes views of an Open Asset Model graph in Go, without a
// model: the outside parties a domain or organization depends on, its
// family and corporate group, the services and network infrastructure it
// exposes, duplicate and misidentified organizations, and the ownership
// signals that suggest links the graph is missing. Lenses read only; what
// they suggest is recorded as proposals by package review.
package lens
