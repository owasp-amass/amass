// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package attribution

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/ai"
	assetdb "github.com/owasp-amass/asset-db"
	"github.com/owasp-amass/asset-db/repository"
	"github.com/owasp-amass/asset-db/repository/sqlite3"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	oamreg "github.com/owasp-amass/open-asset-model/registration"
)

// fakeSession provides what the plugin uses; other methods are unused.
type fakeSession struct {
	et.Session
	id      uuid.UUID
	ctx     context.Context
	cfg     *config.Config
	db      repository.Repository
	scope   *fakeScope
	backlog *fakeBacklog
	stats   *et.SessionStats
}

func (s *fakeSession) ID() uuid.UUID             { return s.id }
func (s *fakeSession) Ctx() context.Context      { return s.ctx }
func (s *fakeSession) Log() *slog.Logger         { return slog.New(slog.DiscardHandler) }
func (s *fakeSession) Config() *config.Config    { return s.cfg }
func (s *fakeSession) Scope() et.Scope           { return s.scope }
func (s *fakeSession) DB() repository.Repository { return s.db }
func (s *fakeSession) Backlog() et.Backlog       { return s.backlog }
func (s *fakeSession) Stats() *et.SessionStats   { return s.stats }
func (s *fakeSession) Done() bool                { return s.ctx.Err() != nil }
func (s *fakeSession) StartTime() time.Time      { return time.Time{} }
func (s *fakeSession) TmpDir() string            { return "" }

// fakeScope holds one in-scope organization and records additions.
type fakeScope struct {
	et.Scope
	org   string
	mu    sync.Mutex
	added []string
}

func (f *fakeScope) IsAssetInScope(a oam.Asset, _ int) (oam.Asset, int) {
	f.mu.Lock()
	defer f.mu.Unlock()

	if o, ok := a.(*oamorg.Organization); ok && o.Name == f.org {
		return a, 100
	}
	for _, k := range f.added {
		if k == a.Key() {
			return a, 100
		}
	}

	return nil, 0
}

func (f *fakeScope) Add(a oam.Asset) bool {
	f.mu.Lock()
	defer f.mu.Unlock()

	f.added = append(f.added, a.Key())
	return true
}

func (f *fakeScope) keys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.added...)
}

type fakeBacklog struct {
	et.Backlog
	mu       sync.Mutex
	enqueued []string
}

func (b *fakeBacklog) Enqueue(e *dbt.Entity) error {
	b.mu.Lock()
	defer b.mu.Unlock()

	b.enqueued = append(b.enqueued, e.Asset.Key())
	return nil
}

// seed stores Colgate's registrant contact and another domain's registrant
// contact with the same phone and address.
func seed(t *testing.T, db repository.Repository) map[string]*dbt.Entity {
	t.Helper()

	ctx := context.Background()
	ents := map[string]*dbt.Entity{}
	create := func(name string, a oam.Asset) {
		e, err := db.CreateAsset(ctx, a)
		if err != nil {
			t.Fatal(err)
		}

		ents[name] = e
	}
	link := func(from, label, to string) {
		if _, err := db.CreateEdge(ctx, &dbt.Edge{Relation: &general.SimpleRelation{Name: label},
			FromEntity: ents[from], ToEntity: ents[to]}); err != nil {
			t.Fatal(err)
		}
	}

	create("colgate", &oamorg.Organization{ID: "colgate", Name: "Colgate University"})
	create("cr-colgate", &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/colgate"})
	create("phone", &oamcon.Phone{Raw: "+1.3152287000", E164: "+1.3152287000"})
	create("loc", &oamcon.Location{Address: "13 Oak Drive, Hamilton NY", City: "Hamilton", Province: "NY", Country: "US"})
	create("dr", &oamreg.DomainRecord{Domain: "colgate.edu"})
	create("colgate.edu", &oamdns.FQDN{Name: "colgate.edu"})
	create("cr-alt", &oamcon.ContactRecord{DiscoveredAt: "https://rdap.example/alumni"})
	create("dr-alt", &oamreg.DomainRecord{Domain: "colgatealumni.org"})
	create("colgatealumni.org", &oamdns.FQDN{Name: "colgatealumni.org"})

	link("cr-colgate", "organization", "colgate")
	link("cr-colgate", "phone", "phone")
	link("cr-colgate", "location", "loc")
	link("dr", "registrant_contact", "cr-colgate")
	link("colgate.edu", "registration", "dr")
	link("cr-alt", "phone", "phone")
	link("cr-alt", "location", "loc")
	link("dr-alt", "registrant_contact", "cr-alt")
	link("colgatealumni.org", "registration", "dr-alt")
	return ents
}

func TestAttributionPassWritesAndWidensScopeOnSQLite(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "attribution.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	ents := seed(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	env := map[string]string{"AMASS_AI_JOURNAL": journal}
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }
	// Duplicate merging has its own test; this one counts only the pass.
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 0

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), db: db,
		scope: &fakeScope{org: "Colgate University"}, backlog: &fakeBacklog{}, stats: &et.SessionStats{}}

	// A signal before any in-scope organization schedules nothing.
	if err := p.check(&et.Event{Entity: ents["colgatealumni.org"], Session: sess}); err != nil {
		t.Fatal(err)
	}
	if n := sess.stats.Background(); n != 0 {
		t.Fatalf("background work = %d before an in-scope organization arrived", n)
	}

	if err := p.check(&et.Event{Entity: ents["colgate"], Session: sess}); err != nil {
		t.Fatal(err)
	}
	if n := sess.stats.Background(); n != 1 {
		t.Fatalf("background work = %d, want the pending pass counted", n)
	}

	deadline := time.Now().Add(20 * time.Second)
	for sess.stats.Background() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if n := sess.stats.Background(); n != 0 {
		t.Fatalf("the pass did not finish: background work = %d", n)
	}

	edges, err := db.OutgoingEdges(context.Background(), ents["cr-alt"], time.Time{}, "organization")
	if err != nil || len(edges) != 1 || edges[0].ToEntity.ID != ents["colgate"].ID {
		t.Fatalf("organization edges from the shared-identity contact = %v, %v", edges, err)
	}

	tags, err := db.FindEdgeTags(context.Background(), edges[0], time.Time{})
	if err != nil || len(tags) != 1 || tags[0].Property.Name() != ai.InferenceSource {
		t.Errorf("edge tags = %v, %v", tags, err)
	}

	added := map[string]bool{}
	for _, k := range sess.scope.keys() {
		added[k] = true
	}
	if !added["colgatealumni.org"] {
		t.Errorf("scope additions = %v, want colgatealumni.org", sess.scope.keys())
	}

	entries, err := (&ai.Journal{Path: journal}).OwnershipEntries()
	if err != nil || len(entries) != 1 || entries[0].Status != ai.ProposalApplied ||
		entries[0].Outcome.Reviewer != ai.AutomaticReviewer {
		t.Errorf("journal = %+v, %v", entries, err)
	}
}

func TestAttributionCanBeTurnedOff(t *testing.T) {
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) {
		if k == "AMASS_AI_ATTRIBUTION" {
			return "off", true
		}
		return "", false
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), scope: &fakeScope{org: "X"},
		stats: &et.SessionStats{}}
	if p.tracker(sess) != nil {
		t.Error("attribution ran with AMASS_AI_ATTRIBUTION=off")
	}
}

func TestAttributionLoadsTheTrainedModel(t *testing.T) {
	dir := t.TempDir()
	model := `{"model_id":"ownership-test","task":"ownership_attribution","feature_version":"ownership-signals-v1",` +
		`"classes":[{"label":"unrelated","bias":0,"weights":{"identity":-1}},` +
		`{"label":"potential_relation","bias":0,"weights":{"identity":1}}],"skip_threshold":0.98,"review_threshold":0.8}`
	if err := os.WriteFile(filepath.Join(dir, ai.AttributionModelFile), []byte(model), 0600); err != nil {
		t.Fatal(err)
	}

	p := NewAttribution().(*plugin)
	env := map[string]string{"AMASS_AI_JOURNAL": filepath.Join(dir, "review.jsonl")}
	p.lookup = func(k string) (string, bool) { v, ok := env[k]; return v, ok }

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: config.NewConfig(), scope: &fakeScope{org: "X"},
		stats: &et.SessionStats{}}
	if tr := p.tracker(sess); tr == nil || tr.model == nil || tr.model.ModelID != "ownership-test" {
		t.Fatalf("tracker = %+v", tr)
	}
}

func TestAttributionSkipsOrganizationsOutsideTheEnumeratedDomains(t *testing.T) {
	db, err := assetdb.New(sqlite3.SQLite, filepath.Join(t.TempDir(), "attribution.db"))
	if err != nil {
		t.Fatal(err)
	}

	defer func() { _ = db.Close() }()
	ents := seed(t, db)
	journal := filepath.Join(t.TempDir(), "review.jsonl")
	p := NewAttribution().(*plugin)
	p.lookup = func(k string) (string, bool) {
		if k == "AMASS_AI_JOURNAL" {
			return journal, true
		}
		return "", false
	}
	p.quiet, p.maxWait, p.mergeCheck = 50*time.Millisecond, time.Second, 0

	// The enumeration asked about example.org, not colgate.edu.
	cfg := config.NewConfig()
	cfg.Scope.Domains = []string{"example.org"}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	sess := &fakeSession{id: uuid.New(), ctx: ctx, cfg: cfg, db: db, scope: &fakeScope{org: "Colgate University"},
		backlog: &fakeBacklog{}, stats: &et.SessionStats{}}

	if err := p.check(&et.Event{Entity: ents["colgate"], Session: sess}); err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(20 * time.Second)
	for sess.stats.Background() != 0 && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	if edges, err := db.OutgoingEdges(context.Background(), ents["cr-alt"], time.Time{}, "organization"); err == nil &&
		len(edges) != 0 {
		t.Errorf("attributed for an organization outside the enumerated domains: %v", edges)
	}
}
