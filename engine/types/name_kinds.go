// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package types

import "context"

// Kinds a NameKindDecider can answer.
const (
	NameKindPerson       = "person"
	NameKindOrganization = "organization"
	NameKindUnclear      = "unclear"
)

// NameKindQuestion asks what a name found in a person's field names, when
// the words and the graph left it uncertain.
type NameKindQuestion struct {
	// Name is the raw name, as the record gave it; Label the field (the
	// relation from the record to the person it names).
	Name  string
	Label string
	// RecordType is the asset type of the record that gave the name, and
	// Source the data source that read it.
	RecordType string
	Source     string
	// Reasons are what the name rules weighed (semantics.NameKindOf), as
	// they were recorded with the name's proposal.
	Reasons []string
	// Evidence is what is known around the name, one fact per line: what
	// the rules weighed, the record's other fields and what it relates to.
	// An answer cites the facts it rests on by number, from 1.
	Evidence []string
}

// NameKindAnswer is a decider's answer: the kind, its confidence (0..100)
// that the kind is right, a one-sentence reason and the numbers of the
// evidence it rests on.
type NameKindAnswer struct {
	Kind       string
	Confidence int
	Reason     string
	Cites      []int
	// DecidedBy names what answered (a classifier or a model) when it is
	// not the decider itself; AdviceOnly keeps a confident answer from
	// being applied, so it is recorded as advice.
	DecidedBy  string
	AdviceOnly bool
}

// NameKindDecider answers what an uncertain name names. The engine asks it
// in the background (support.BackgroundLane), and its answer is applied or
// kept as advice by the attribution mode; it writes nothing itself.
type NameKindDecider interface {
	// Name names the decider in the journal and the log, such as a model.
	Name() string
	Decide(ctx context.Context, q *NameKindQuestion) (NameKindAnswer, error)
}
