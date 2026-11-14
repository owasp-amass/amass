// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package ai answers questions about an Open Asset Model graph. It plans a
// question into a bounded, read-only query (with or without a model), runs
// it, ranks the evidence and writes the answer, and it ties together the
// subpackages:
//
//   - graph: the read-only view of the asset database every component uses
//   - llm: the model providers (Anthropic, Ollama) and their usage metering
//   - lens: computed views of the graph (vendors, family, services, network,
//     duplicates, identity and more), each answered in Go without a model
//   - review: the proposal journal, evidence bundles and the decisions that
//     write accepted proposals back
package ai
