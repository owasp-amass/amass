// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package llm

import (
	"context"
	"sync"
	"time"
)

// ModelUsage totals the model requests made during one investigation.
// Token counts are as reported by the provider (zero when it reports none).
type ModelUsage struct {
	Calls        int   `json:"calls"`
	InputTokens  int   `json:"input_tokens"`
	OutputTokens int   `json:"output_tokens"`
	ModelMS      int64 `json:"model_ms"`
}

// MeteredModel records usage for every request through the wrapped model,
// including failed ones, and keeps structured generation available when the
// wrapped provider supports it.
type MeteredModel struct {
	Inner Model
	mu    sync.Mutex
	usage ModelUsage
}

func (m *MeteredModel) record(start time.Time, r Response) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usage.Calls++
	m.usage.InputTokens += r.InputTokens
	m.usage.OutputTokens += r.OutputTokens
	m.usage.ModelMS += time.Since(start).Milliseconds()
}

func (m *MeteredModel) Generate(ctx context.Context, h []Message, specs []ToolSpec) (Response, error) {
	start := time.Now()
	r, err := m.Inner.Generate(ctx, h, specs)
	m.record(start, r)
	return r, err
}

func (m *MeteredModel) GenerateStructured(ctx context.Context, h []Message, schema JSONSchema) (Response, error) {
	start := time.Now()
	var (
		r   Response
		err error
	)
	if sm, ok := m.Inner.(StructuredModel); ok {
		r, err = sm.GenerateStructured(ctx, h, schema)
	} else {
		r, err = m.Inner.Generate(ctx, h, nil)
	}

	m.record(start, r)
	return r, err
}

func (m *MeteredModel) Snapshot() *ModelUsage {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.usage
	return &u
}
