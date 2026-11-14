// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package ai answers questions about an Open Asset Model graph in plain
// language. It plans a question into a bounded, read-only query (with a
// model, or without one when the question compiles directly), runs it,
// ranks the evidence and writes the answer, answering many kinds of
// question with the lenses of package internal/lens.
//
// Everything under internal/ai is what can use a model: this package, the
// providers in llm, the MCP server in mcp, the trained classifiers in
// classify and the amass ai command in cli. The graph view
// (internal/graph), the lenses (internal/lens), the review journal
// (internal/review) and the semantics data (internal/semantics) run without
// one, during enumerations and from amass lens and amass review, and never
// import internal/ai.
package ai
