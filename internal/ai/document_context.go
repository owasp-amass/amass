// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"fmt"
	"strings"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// charsPerToken estimates how many characters of a document's text one token
// holds. English prose runs near 4; markup, tables and other languages run
// lower, so a conservative 3 keeps the estimate from falling short.
const charsPerToken = 3

// documentRequestTokens estimates the context one document model request
// needs: the instructions, one chunk of the document and the reply.
func documentRequestTokens(chunkChars, replyTokens int) int {
	prompt := len(documentPrompt(documentVocabulary()))
	return (prompt+chunkChars)/charsPerToken + replyTokens
}

// DocumentContextWarnings checks that the configured document model has room
// for one request (the instructions, a chunk and the reply), and, for an
// Ollama model, that context_tokens is within the window the model was
// trained with. It returns one plain sentence per problem, naming the
// setting to change, or none. Only an Ollama model is asked anything.
func DocumentContextWarnings(ctx context.Context, d *config.DocumentModelSettings) []string {
	if d == nil || !d.Enabled || !strings.EqualFold(strings.TrimSpace(d.Provider), "ollama") {
		return nil
	}

	chunk, reply, window := d.ChunkChars, d.MaxTokens, d.ContextTokens
	if chunk == 0 {
		chunk = DefaultDocumentChunk
	}
	if reply == 0 {
		reply = DefaultDocumentReplyTokens
	}
	if window == 0 {
		window = DefaultDocumentContextTokens
	}

	var out []string
	if m, _, _, err := DocumentModel(d); err == nil {
		if om, ok := m.(llm.OllamaModel); ok {
			trained, err := om.ContextLength(ctx)
			switch {
			case err != nil:
				out = append(out, fmt.Sprintf("could not read %s's context window from Ollama: %v", d.Model, err))
			case trained > 0 && window > trained:
				out = append(out, fmt.Sprintf("options.ai.documents.context_tokens is %d, but %s was trained "+
					"with %d; set context_tokens to %d or less", window, d.Model, trained, trained))
				window = trained
			}
		}
	}

	if need := documentRequestTokens(chunk, reply); need > window {
		fit := (window - reply) * charsPerToken
		fit -= len(documentPrompt(documentVocabulary()))
		advice := fmt.Sprintf("lower options.ai.documents.chunk_chars to %d or less", max(fit, 0))
		if fit < 2000 {
			advice = "raise options.ai.documents.context_tokens, or lower max_tokens"
		}
		out = append(out, fmt.Sprintf("one document request needs about %d tokens (instructions, a %d-character "+
			"chunk and a %d-token reply), more than the %d-token context; %s", need, chunk, reply, window, advice))
	}
	return out
}
