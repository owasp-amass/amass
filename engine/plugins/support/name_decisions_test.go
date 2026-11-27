// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package support

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/review"
	"github.com/owasp-amass/open-asset-model/contact"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// fakeNameDecider answers every name the same way and keeps the questions.
type fakeNameDecider struct {
	answer et.NameKindAnswer
	mu     sync.Mutex
	asked  []*et.NameKindQuestion
}

func (f *fakeNameDecider) Name() string { return "fake" }

func (f *fakeNameDecider) Decide(_ context.Context, q *et.NameKindQuestion) (et.NameKindAnswer, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.asked = append(f.asked, q)
	return f.answer, nil
}

func (f *fakeNameDecider) questions() []*et.NameKindQuestion {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.asked
}

// An uncertain name is asked about beside the pipeline: under attribution
// auto, a confident answer is applied as an automatic decision, and a less
// confident one, or one that may only advise, is kept on the proposal as
// advice.
func TestUncertainNameAsked(t *testing.T) {
	for _, tc := range []struct {
		conf       int
		adviceOnly bool
		applied    bool
	}{{95, false, true}, {70, false, false}, {95, true, false}} {
		sess := plugintest.NewSession(t)
		d := &fakeNameDecider{answer: et.NameKindAnswer{Kind: et.NameKindOrganization, Confidence: tc.conf,
			Reason: "a company's name", Cites: []int{1}, AdviceOnly: tc.adviceOnly}}
		sess.SetNameKinds(d)

		ctx := context.Background()
		cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: "https://example.net/whois"})
		org := sess.Asset(t, &oamorg.Organization{ID: "acme:1", Name: "Acme"})
		sess.Edge(t, cr, &oamgen.SimpleRelation{Name: "organization"}, org)
		KeepUncertainName(ctx, sess, cr, "person", "Sarah Church", []string{"two words a parser reads as a person"},
			&et.Source{Name: "WHOIS"})

		for deadline := time.Now().Add(5 * time.Second); sess.Stats().Background() != 0 || len(d.questions()) == 0; {
			if time.Now().After(deadline) {
				t.Fatalf("confidence %d: the name was not asked about", tc.conf)
			}
			time.Sleep(10 * time.Millisecond)
		}

		q := d.questions()[0]
		joined := strings.Join(q.Evidence, "\n")
		if q.Name != "Sarah Church" || q.Label != "person" || q.Source != "WHOIS" || len(q.Reasons) != 1 ||
			!strings.Contains(joined, "two words a parser reads as a person") ||
			!strings.Contains(joined, `the record's organization is the Organization "Acme"`) {
			t.Errorf("confidence %d: the question %+v", tc.conf, q)
		}

		names, err := ReviewJournal(sess, func(string) (string, bool) { return "", false }).NameKindEntries()
		if err != nil || len(names) != 1 {
			t.Fatalf("confidence %d: entries %+v, %v", tc.conf, names, err)
		}
		e := names[0]
		if tc.applied {
			if e.Status != review.ProposalApplied || e.Outcome.Reviewer != "amass-ai (fake)" ||
				e.Outcome.Kind != et.NameKindOrganization {
				t.Errorf("confidence %d: entry %+v outcome %+v", tc.conf, e, e.Outcome)
			}
			continue
		}
		if e.Status != review.ProposalPending || e.Advice == nil || e.Advice.Confidence != tc.conf ||
			len(e.Advice.Cites) != 1 || e.Advice.Cites[0] != q.Evidence[0] {
			t.Errorf("confidence %d: entry %+v advice %+v", tc.conf, e, e.Advice)
		}
	}
}

// One name in one field is asked about once: records naming it while it is
// asked, and after, take the same answer, so each gets the advice without
// another question.
func TestUncertainNameAskedOncePerName(t *testing.T) {
	sess := plugintest.NewSession(t)
	d := &fakeNameDecider{answer: et.NameKindAnswer{Kind: et.NameKindPerson, Confidence: 70,
		Reason: "a login made of an initial and a surname"}}
	sess.SetNameKinds(d)

	ctx := context.Background()
	record := func(i int) {
		cr := sess.Asset(t, &contact.ContactRecord{DiscoveredAt: fmt.Sprintf("https://example.net/doc%d", i)})
		KeepUncertainName(ctx, sess, cr, "person", []string{"jgordon", "JGordon", " jgordon "}[i%3],
			[]string{"it does not read as a person's name"}, &et.Source{Name: "Documents"})
	}
	settle := func() {
		for deadline := time.Now().Add(5 * time.Second); sess.Stats().Background() != 0 || len(d.questions()) == 0; {
			if time.Now().After(deadline) {
				t.Fatal("the name was not asked about")
			}
			time.Sleep(10 * time.Millisecond)
		}
	}
	for i := range 3 {
		record(i)
	}
	settle()
	record(3)
	settle()

	if n := len(d.questions()); n != 1 {
		t.Errorf("the name was asked %d times, want once", n)
	}
	names, err := ReviewJournal(sess, func(string) (string, bool) { return "", false }).NameKindEntries()
	if err != nil || len(names) != 4 {
		t.Fatalf("entries %+v, %v", names, err)
	}
	for _, e := range names {
		if e.Status != review.ProposalPending || e.Advice == nil || e.Advice.Kind != et.NameKindPerson ||
			e.Advice.Confidence != 70 {
			t.Errorf("entry %s: %+v advice %+v", e.Proposal.ID, e, e.Advice)
		}
	}
}
