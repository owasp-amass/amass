// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"

	"github.com/owasp-amass/amass/v5/internal/ai"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

// maxQueryFileBytes bounds a -query file; real queries are a few KB.
const maxQueryFileBytes = 1 << 20

// providerSettings configures one model client (see ai.ModelSettings).
type providerSettings = ai.ModelSettings

// newProvider builds the configured model client and checks its endpoint.
func newProvider(s providerSettings) (llm.Model, error) { return ai.NewModel(s) }

// readQuery loads a Query from path, or from stdin when path is "-". Unknown
// fields are rejected so a mistyped key cannot silently widen a query.
func readQuery(path string, stdin io.Reader) (ai.Query, error) {
	var q ai.Query
	r := stdin
	if path != "-" {
		f, err := os.Open(path)
		if err != nil {
			return q, fmt.Errorf("open query: %w", err)
		}

		defer func() { _ = f.Close() }()
		r = f
	}

	raw, err := io.ReadAll(io.LimitReader(r, maxQueryFileBytes+1))
	if err != nil {
		return q, fmt.Errorf("read query: %w", err)
	}
	if len(raw) > maxQueryFileBytes {
		return q, errors.New("query file exceeds 1 MiB")
	}

	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&q); err != nil {
		return q, fmt.Errorf("decode query: %w", err)
	}
	if dec.More() {
		return q, errors.New("query file must hold exactly one JSON object")
	}

	return q, nil
}

func writeJSON(out io.Writer, v any) error {
	pretty, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}

	_, err = fmt.Fprintln(out, string(pretty))
	return err
}

// writeInvestigation prints an investigation as json, text or mermaid.
func writeInvestigation(out io.Writer, format string, result ai.Investigation) error {
	switch format {
	case "text":
		if result.Narrative != nil && result.Narrative.Verified {
			if _, err := fmt.Fprintln(out, ai.NarrativeText(*result.Narrative)+"\n"); err != nil {
				return err
			}
		}

		_, err := fmt.Fprintln(out, result.Answer)
		return err
	case "mermaid":
		if result.Diagram == "" {
			return fmt.Errorf("investigation did not produce a diagram: %s", result.Answer)
		}

		_, err := fmt.Fprint(out, result.Diagram)
		return err
	case "json":
		return writeJSON(out, result)
	default:
		return errors.New("-format must be json, text, or mermaid")
	}
}

// writeTrace prints one line per investigation stage and the model usage,
// so slow model calls are visible without reading the JSON.
func writeTrace(w io.Writer, result ai.Investigation) {
	for _, ev := range result.Trace {
		status := ""
		if ev.Incomplete {
			status = " (incomplete)"
		}

		_, _ = fmt.Fprintf(w, "trace: %-20s %8.1fs%s %s\n", ev.Stage, float64(ev.DurationMS)/1000, status, ev.Detail)
	}
	if u := result.Usage; u != nil {
		_, _ = fmt.Fprintf(w, "trace: model calls=%d input_tokens=%d output_tokens=%d model_time=%.1fs\n",
			u.Calls, u.InputTokens, u.OutputTokens, float64(u.ModelMS)/1000)
	}
}
