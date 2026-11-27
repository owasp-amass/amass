// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package ai

import (
	"context"
	"errors"
	"testing"

	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai/llm"
)

func TestModelBreaker(t *testing.T) {
	var told []error
	b := &ModelBreaker{OnOpen: func(err error) { told = append(told, err) }}
	down := errors.New("connection refused")

	b.Record(down)
	b.Record(down)
	b.Record(nil) // a success resets the count
	b.Record(down)
	b.Record(context.Canceled) // the session ending is not the model's failure
	b.Record(down)
	if !b.Allow() {
		t.Fatal("stopped before three failures in a row")
	}
	b.Record(down)
	b.Record(down)
	if b.Allow() || len(told) != 1 {
		t.Fatalf("allow %v after three failures, told %v", b.Allow(), told)
	}
	if n := b.Requests(); n != 8 {
		t.Errorf("%d requests counted, not 8", n)
	}

	var none *ModelBreaker
	none.Record(down)
	if !none.Allow() || none.Requests() != 0 {
		t.Error("a nil breaker stopped the model or counted a request")
	}
}

// failingModel fails every request.
type failingModel struct{ calls int }

func (m *failingModel) Generate(context.Context, []llm.Message, []llm.ToolSpec) (llm.Response, error) {
	m.calls++
	return llm.Response{}, errors.New("503 service unavailable")
}

// Once the main model has failed three requests in a row, the session's
// deciders stop asking it: names are left for review and admissions to the
// evidence rule, at once.
func TestDecidersStopAskingAFailingModel(t *testing.T) {
	m := &failingModel{}
	b := &ModelBreaker{}
	names := &NameKindModel{Model: m, ModelID: "test", Breaker: b}
	q := &et.NameKindQuestion{Name: "Sarah Church", Label: "person", Evidence: []string{"x"}}
	for i := 0; i < 5; i++ {
		_, _ = names.Decide(context.Background(), q)
	}
	if m.calls != DefaultModelFailures {
		t.Errorf("the model was asked %d times, want %d", m.calls, DefaultModelFailures)
	}
	if _, err := names.Decide(context.Background(), q); !errors.Is(err, ErrModelStopped) {
		t.Errorf("a stopped model's error: %v", err)
	}

	admit := &AdmissionModel{Model: m, ModelID: "test", Breaker: b}
	if _, ok, _ := admit.Decide(context.Background(), nil, admissionRequest(et.StrengthSupporting)); ok {
		t.Error("a stopped model still took an admission")
	}
}

// A reply the model gave but that cannot be used is not a failure.
func TestBreakerIgnoresUnusableReplies(t *testing.T) {
	b := &ModelBreaker{}
	names := &NameKindModel{Model: &replyModel{reply: "not json"}, ModelID: "test", Breaker: b}
	for i := 0; i < 5; i++ {
		_, _ = names.Decide(context.Background(), &et.NameKindQuestion{Name: "Sarah Church", Evidence: []string{"x"}})
	}
	if !b.Allow() {
		t.Error("unusable replies stopped the model")
	}
}
