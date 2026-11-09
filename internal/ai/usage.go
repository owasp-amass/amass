// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

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

// meteredModel records usage for every request through the wrapped model,
// including failed ones, and keeps structured generation available when the
// wrapped provider supports it.
type meteredModel struct {
	inner Model
	mu    sync.Mutex
	usage ModelUsage
}

func (m *meteredModel) record(start time.Time, r Response) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.usage.Calls++
	m.usage.InputTokens += r.InputTokens
	m.usage.OutputTokens += r.OutputTokens
	m.usage.ModelMS += time.Since(start).Milliseconds()
}

func (m *meteredModel) Generate(ctx context.Context, h []Message, specs []ToolSpec) (Response, error) {
	start := time.Now()
	r, err := m.inner.Generate(ctx, h, specs)
	m.record(start, r)
	return r, err
}

func (m *meteredModel) GenerateStructured(ctx context.Context, h []Message, schema JSONSchema) (Response, error) {
	start := time.Now()
	var (
		r   Response
		err error
	)
	if sm, ok := m.inner.(StructuredModel); ok {
		r, err = sm.GenerateStructured(ctx, h, schema)
	} else {
		r, err = m.inner.Generate(ctx, h, nil)
	}

	m.record(start, r)
	return r, err
}

func (m *meteredModel) snapshot() *ModelUsage {
	m.mu.Lock()
	defer m.mu.Unlock()
	u := m.usage
	return &u
}

// metered returns a copy of a whose model records usage, and the meter.
// A nil model stays nil so model-free queries keep failing closed.
func (a Agent) metered() (Agent, *meteredModel) {
	if a.Model == nil {
		return a, nil
	}
	if m, ok := a.Model.(*meteredModel); ok {
		return a, m
	}

	m := &meteredModel{inner: a.Model}
	a.Model = m
	return a, m
}
