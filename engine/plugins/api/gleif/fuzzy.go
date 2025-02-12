// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package gleif

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	"github.com/owasp-amass/amass/v4/utils/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

type fuzzyCompletions struct {
	name   string
	plugin *gleif
}

func (fc *fuzzyCompletions) check(e *et.Event) error {
	_, ok := e.Entity.Asset.(*org.Organization)
	if !ok {
		return errors.New("failed to extract the Organization asset")
	}

	since, err := support.TTLStartTime(e.Session.Config(), string(oam.Organization), string(oam.Organization), fc.name)
	if err != nil {
		return err
	}

	var id *dbt.Entity
	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, fc.plugin.source, since) {
		id = fc.lookup(e, e.Entity, fc.plugin.source, since)
	} else {
		id = fc.query(e, e.Entity, fc.plugin.source)
		support.MarkAssetMonitored(e.Session, e.Entity, fc.plugin.source)
	}

	if id != nil {
		fc.process(e, e.Entity, id, fc.plugin.source)
	}
	return nil
}

func (fc *fuzzyCompletions) lookup(e *et.Event, o *dbt.Entity, src *et.Source, since time.Time) *dbt.Entity {
	var ids []*dbt.Entity

	if edges, err := e.Session.Cache().OutgoingEdges(o, since, "id"); err == nil {
		for _, edge := range edges {
			if a, err := e.Session.Cache().FindEntityById(edge.ToEntity.ID); err == nil && a != nil {
				if _, ok := a.Asset.(*general.Identifier); ok {
					ids = append(ids, a)
				}
			}
		}
	}

	for _, ident := range ids {
		if id := ident.Asset.(*general.Identifier); id != nil && id.Type == general.LEICode {
			return ident
		}
	}
	return nil
}

type gleifFuzzy struct {
	Data []struct {
		Type       string `json:"type"`
		Attributes struct {
			Value string `json:"value"`
		} `json:"attributes"`
		Relationships struct {
			LEIRecords struct {
				Data struct {
					Type string `json:"type"`
					ID   string `json:"id"`
				} `json:"data"`
				Links struct {
					Related string `json:"related"`
				} `json:"links"`
			} `json:"lei-records"`
		} `json:"relationships"`
	} `json:"data"`
}

func (fc *fuzzyCompletions) query(e *et.Event, orgent *dbt.Entity, src *et.Source) *dbt.Entity {
	o := orgent.Asset.(*org.Organization)
	u := "https://api.gleif.org/api/v1/fuzzycompletions?field=fulltext&q=" + url.QueryEscape(o.Name)

	fc.plugin.rlimit.Take()
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: u})
	if err != nil || resp.Body == "" {
		return nil
	}

	var result gleifFuzzy
	if err := json.Unmarshal([]byte(resp.Body), &result); err != nil || len(result.Data) == 0 {
		return nil
	}

	var lei *general.Identifier
	for _, d := range result.Data {
		if strings.EqualFold(d.Attributes.Value, o.Name) {
			lei = &general.Identifier{
				UniqueID: fmt.Sprintf("%s:%s", general.LEICode, d.Relationships.LEIRecords.Data.ID),
				EntityID: d.Relationships.LEIRecords.Data.ID,
				Type:     general.LEICode,
			}
		}
	}
	if lei == nil {
		return nil
	}

	rec, err := fc.plugin.getLEIRecord(e, lei, src)
	if err == nil {
		return nil
	}

	return fc.store(e, orgent, lei, fc.plugin.source)
}

func (fc *fuzzyCompletions) store(e *et.Event, orgent *dbt.Entity, id *general.Identifier, src *et.Source) *dbt.Entity {
	return nil
}

func (fc *fuzzyCompletions) process(e *et.Event, orgent, ident *dbt.Entity, src *et.Source) {
}
