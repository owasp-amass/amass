// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package graph is the read-only view of an Open Asset Model graph that the
// AI components share: the assets and relations, the bounded readers that
// page edges and evidence, the schema and relationship semantics catalogs,
// and the small naming helpers every answer uses. It writes nothing and
// depends on no other AI package.
package graph
