// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package breach

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/graph"
	"github.com/owasp-amass/amass/v5/internal/semantics/breachsources"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const xonFixture = `{
	"ExposedBreaches": {"breaches_details": [
		{"breach": "Adobe", "xposed_data": "Email addresses;Passwords", "xposed_date": "2013", "verified": "Yes"},
		{"breach": "LinkedIn", "xposed_data": "Email addresses;Passwords", "xposed_date": "2016", "verified": "Yes"}
	]}
}`

func testPlugin() *plugin {
	p := NewBreachExposure().(*plugin)
	p.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	return p
}

// TestQuerySource parses a stubbed XposedOrNot response into breach records.
func TestQuerySource(t *testing.T) {
	sess := plugintest.NewSession(t)
	p := testPlugin()

	var gotURL string
	p.fetch = func(_ context.Context, _ et.Session, reqURL, _ string) ([]byte, error) {
		gotURL = reqURL
		return []byte(xonFixture), nil
	}

	src, ok := breachsources.SourceByKey("xposedornot")
	require.True(t, ok)

	recs := p.querySource(sess, src, "jane@example.com", "")
	require.Len(t, recs, 2)
	assert.Contains(t, gotURL, "jane%40example.com", "email should be URL-encoded")
	assert.Equal(t, "Adobe", recs[0].Breach)
	assert.Equal(t, "XposedOrNot", recs[0].Source)
	assert.Equal(t, "2013", recs[0].Date)
	assert.Contains(t, recs[0].DataClasses, "Passwords")
}

// TestRecordWritesBreachProperties stores the breaches as metadata properties
// on the email identifier and reads them back.
func TestRecordWritesBreachProperties(t *testing.T) {
	sess := plugintest.NewSession(t)
	p := testPlugin()

	id := sess.Asset(t, &oamgen.Identifier{UniqueID: "email:jane@example.com", ID: "jane@example.com",
		Type: oamgen.EmailAddress})
	e := &et.Event{Entity: id, Session: sess, Dispatcher: &plugintest.Dispatcher{}}

	records := []graph.BreachInfo{
		{Breach: "Adobe", Date: "2013", DataClasses: []string{"Email addresses", "Passwords"}, Source: "XposedOrNot", Verified: true},
		{Breach: "LinkedIn", Date: "2016", DataClasses: []string{"Email addresses", "Passwords"}, Source: "XposedOrNot"},
	}
	require.NoError(t, p.record(e, records))

	// Read the stored breach properties back and confirm they are metadata.
	tags, err := sess.DB().FindEntityTags(context.Background(), id, time.Time{})
	require.NoError(t, err)

	breaches := map[string]graph.BreachInfo{}
	for _, tag := range tags {
		sp, ok := tag.Property.(*oamgen.SimpleProperty)
		if !ok || sp.PropertyName != graph.BreachProperty {
			continue
		}
		var b graph.BreachInfo
		require.NoError(t, json.Unmarshal([]byte(sp.PropertyValue), &b))
		breaches[b.Breach] = b
		// Metadata only: no raw password/credential field leaks into the value.
		assert.NotContains(t, strings.ToLower(sp.PropertyValue), "password_plaintext")
	}
	require.Len(t, breaches, 2)
	assert.Equal(t, "2013", breaches["Adobe"].Date)
	assert.True(t, breaches["Adobe"].Verified)
	assert.Contains(t, breaches["LinkedIn"].DataClasses, "Passwords")
}

// TestCredentialOptIn checks a source is skipped unless the operator enabled
// it, and a keyed source needs a key.
func TestCredentialOptIn(t *testing.T) {
	sess := plugintest.NewSession(t)
	p := testPlugin()

	free, _ := breachsources.SourceByKey("xposedornot")
	keyed, _ := breachsources.SourceByKey("hibp")

	// Nothing configured: the free source is skipped.
	if _, ok := p.credential(sess, free); ok {
		t.Error("a source with no data-source config should be skipped")
	}

	// Operator enables the free source and the keyed one, the keyed one
	// without a key.
	sess.Config().DataSrcConfigs = &config.DataSourceConfig{Datasources: []*config.DataSource{
		{Name: free.Name},
		{Name: keyed.Name},
	}}
	if _, ok := p.credential(sess, free); !ok {
		t.Error("an enabled free source should run")
	}
	if _, ok := p.credential(sess, keyed); ok {
		t.Error("a keyed source without a key should be skipped")
	}

	// With a key, the keyed source runs and the key is returned.
	sess.Config().DataSrcConfigs.Datasources[1].Creds = map[string]*config.Credentials{
		"account": {Apikey: "secret"},
	}
	if key, ok := p.credential(sess, keyed); !ok || key != "secret" {
		t.Errorf("a keyed source with a key should run: key=%q ok=%v", key, ok)
	}
}
