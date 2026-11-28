// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package hubs

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/owasp-amass/amass/v5/internal/coord"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// A value far above the typical holder count is a hub, an ordinary spread
// is not, and too few values leave the caller's limit.
func TestDerive(t *testing.T) {
	spread := dbt.DegreeHistogram{1: 400, 2: 300, 4: 200, 8: 100, 16: 40, 1000: 1}
	th := Derive("phone|in", spread)
	limit, derived := th.For(50)
	if !derived || limit < 16 || limit >= 1000 {
		t.Errorf("limit %d (derived %v) does not set the 1000-holder value apart from the 16: %+v", limit, derived, th)
	}
	if th.Key != "phone|in" || th.Values != 1041 {
		t.Errorf("threshold = %+v", th)
	}

	// most values held once: the spread comes from the mean deviation, and
	// the floor keeps small counts ordinary
	ones := dbt.DegreeHistogram{1: 2000, 3: 10, 500: 1}
	if limit, derived := Derive("phone|in", ones).For(50); !derived || limit != semantics.HubsCatalog().Floor {
		t.Errorf("limit %d (derived %v), not the floor", limit, derived)
	}

	few := dbt.DegreeHistogram{1: 10, 2: 5, 100: 1}
	if limit, derived := Derive("phone|in", few).For(50); derived || limit != 50 {
		t.Errorf("a small sample gave %d (derived %v), not the fallback", limit, derived)
	}
	if limit, derived := Derive("phone|in", dbt.DegreeHistogram{1: 5000}).For(50); derived || limit != 50 {
		t.Errorf("counts that never vary gave %d (derived %v), not the fallback", limit, derived)
	}
}

// fakeDegrees answers degree reads from a histogram, counting them.
type fakeDegrees struct {
	h     dbt.DegreeHistogram
	err   error
	reads int
	where []string
}

func (f *fakeDegrees) DegreeHistograms(_ context.Context, _ string, labels []string) (map[string]dbt.DegreeHistogram,
	error) {
	f.reads++
	if f.err != nil {
		return nil, f.err
	}
	return map[string]dbt.DegreeHistogram{labels[0]: f.h}, nil
}

func (f *fakeDegrees) DegreeHistogramWhere(_ context.Context, _, label string, atype oam.AssetType, key,
	value string) (dbt.DegreeHistogram, error) {
	f.reads++
	f.where = append(f.where, label+" "+string(atype)+"."+key+"="+value)
	if f.err != nil {
		return nil, f.err
	}
	return f.h, nil
}

// A filtered edge source reads its own histogram under its own key: the
// fingerprints of one type.
func TestFilteredEdgeSource(t *testing.T) {
	degrees := &fakeDegrees{h: dbt.DegreeHistogram{1: 400, 2: 300, 4: 200, 8: 100, 16: 40, 1000: 1}}
	table := &Table{degrees: degrees, known: map[string]Threshold{}}
	favicon := Source{Label: "fingerprint", Direction: "in", AssetType: "Identifier", Property: "id_type",
		Value: "favicon_mmh3"}
	if n := table.Limit(context.Background(), favicon, 50); n == 50 {
		t.Error("the favicon source gave the fallback")
	}
	if len(degrees.where) != 1 || degrees.where[0] != "fingerprint Identifier.id_type=favicon_mmh3" {
		t.Errorf("reads = %v", degrees.where)
	}
	if favicon.Key() != "fingerprint|in|identifier.id_type=favicon_mmh3" {
		t.Errorf("key %q", favicon.Key())
	}
}

// A table computes a label's threshold once, records it, and another table
// on the same database takes the record; a failed read gives the fallback.
func TestTable(t *testing.T) {
	ctx := context.Background()
	phone := Source{Label: "phone", Direction: "in"}
	store := &coord.FakeStore{}
	degrees := &fakeDegrees{h: dbt.DegreeHistogram{1: 400, 2: 300, 4: 200, 8: 100, 16: 40, 1000: 1}}
	first := &Table{degrees: degrees, topic: &coord.Topic{Store: store, Name: Topic}, known: map[string]Threshold{}}

	limit := first.Limit(ctx, phone, 50)
	if limit == 50 || first.Limit(ctx, Source{Label: "PHONE", Direction: "in"}, 50) != limit || degrees.reads != 1 {
		t.Fatalf("limit %d after %d reads", limit, degrees.reads)
	}
	if recs := store.Records(); len(recs) != 1 || recs[0].Key != "phone|in" {
		t.Fatalf("records = %+v", recs)
	}

	second := &Table{degrees: degrees, topic: &coord.Topic{Store: store, Name: Topic}, known: map[string]Threshold{}}
	if second.Limit(ctx, phone, 50) != limit || degrees.reads != 1 {
		t.Errorf("the second table read the database again (%d reads)", degrees.reads)
	}

	failing := &Table{degrees: &fakeDegrees{err: errors.New("down")}, known: map[string]Threshold{}}
	if n := failing.Limit(ctx, phone, 50); n != 50 {
		t.Errorf("a failed read gave %d, not the fallback", n)
	}
	var none *Table
	if n := none.Limit(ctx, phone, 50); n != 50 {
		t.Errorf("no table gave %d, not the fallback", n)
	}
}

// fakeValues answers value histograms, recording what each read asked for.
type fakeValues struct {
	h     dbt.DegreeHistogram
	asked []string
}

func (f *fakeValues) TagValueHistogram(_ context.Context, atype oam.AssetType, name string,
	prefixes []string) (dbt.DegreeHistogram, error) {
	f.asked = append(f.asked, "tag "+string(atype)+" "+name+" "+strings.Join(prefixes, ","))
	return f.h, nil
}

func (f *fakeValues) AttributeValueHistogram(_ context.Context, atype oam.AssetType,
	key string) (dbt.DegreeHistogram, error) {
	f.asked = append(f.asked, "attr "+string(atype)+" "+key)
	return f.h, nil
}

// A tag or attribute source reads its own value histogram, under its own key;
// without value histograms the fallback applies.
func TestValueSources(t *testing.T) {
	ctx := context.Background()
	values := &fakeValues{h: dbt.DegreeHistogram{1: 400, 2: 300, 4: 200, 8: 100, 16: 40, 1000: 1}}
	table := &Table{values: values, known: map[string]Threshold{}}

	token := Source{AssetType: "FQDN", Property: "dns_record", Prefixes: []string{"google-site-verification="}}
	skid := Source{AssetType: "TLSCertificate", Property: "subject_key_id", Attribute: true}
	if n := table.Limit(ctx, token, 50); n == 50 {
		t.Error("the token source gave the fallback")
	}
	if n := table.Limit(ctx, skid, 50); n == 50 {
		t.Error("the attribute source gave the fallback")
	}
	if len(values.asked) != 2 || values.asked[0] != "tag FQDN dns_record google-site-verification=" ||
		values.asked[1] != "attr TLSCertificate subject_key_id" {
		t.Errorf("reads = %v", values.asked)
	}
	if token.Key() != "tag:fqdn|dns_record|google-site-verification=" || skid.Key() != "attr:tlscertificate|subject_key_id" {
		t.Errorf("keys %q and %q", token.Key(), skid.Key())
	}

	degreesOnly := &Table{degrees: &fakeDegrees{}, known: map[string]Threshold{}}
	if n := degreesOnly.Limit(ctx, token, 50); n != 50 {
		t.Errorf("a database without value histograms gave %d, not the fallback", n)
	}
}
