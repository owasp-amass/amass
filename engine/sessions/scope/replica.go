// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scope

import (
	"encoding/json"
	"fmt"
	"log/slog"

	"github.com/owasp-amass/amass/v5/engine/api/client"
	"github.com/owasp-amass/amass/v5/internal/coord"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamcon "github.com/owasp-amass/open-asset-model/contact"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

// The kinds of the work topic's records: a scope entry one worker of a job
// added, and a decision one made about admitting an asset.
const (
	ScopeAddKind  = "scope_add"
	AdmissionKind = "admission"
)

// scopeRecord is a scope_add record's data.
type scopeRecord struct {
	// Worker is the session that added the entry.
	Worker string          `json:"worker"`
	Type   string          `json:"type"`
	Entry  json.RawMessage `json:"entry"`
	// Admitted is set when an admission decision added it.
	Admitted bool `json:"admitted,omitempty"`
}

// replica shares a scope with the other workers of a job.
type replica struct {
	topic  *coord.Topic
	leases *coord.Leases
	job    string
	worker string
}

// addEntry adds a scope entry, notes when an admission added it, and, when
// publish is set, tells the job's other workers.
func (s *Scope) addEntry(e oam.Asset, admitted, publish bool) bool {
	var added bool
	switch v := e.(type) {
	case *oamdns.FQDN:
		added = s.addFQDN(v)
	case *oamnet.IPAddress:
		added = s.addIPAddress(v)
	case *oamnet.Netblock:
		added = s.addNetblock(v)
	case *oamnet.AutonomousSystem:
		added = s.addAutonomousSystem(v)
	case *oamorg.Organization:
		added = s.addOrganization(v)
	case *oamcon.StreetAddress:
		added = s.addStreetAddress(v)
	}
	if !added {
		return false
	}

	if admitted {
		s.adm.Lock()
		if s.adm.entries == nil {
			s.adm.entries = map[string]bool{}
		}
		s.adm.entries[admissionKey(e)] = true
		s.adm.Unlock()
	}
	if publish {
		s.publish(e, admitted)
	}
	return true
}

// Replicate shares the scope with the other workers of job, through the
// journal topic (the work topic): each entry the scope adds from now on is
// appended as a scope_add record, and each decision a decider makes as an
// admission record, and Apply takes the other workers' records. leases,
// when set, give one worker at a time a model's decision about an asset.
// worker names this session. The entries a worker starts with come from the
// job's configuration and are not recorded.
func (s *Scope) Replicate(topic *coord.Topic, leases *coord.Leases, job, worker string) {
	if topic == nil || job == "" || worker == "" {
		return
	}
	s.rep.Store(&replica{topic: topic, leases: leases, job: job, worker: worker})
}

// publish appends a new entry to the job's records.
func (s *Scope) publish(e oam.Asset, admitted bool) {
	raw, err := json.Marshal(e)
	if err != nil {
		return
	}
	s.appendRecord(ScopeAddKind, e.Key(), func(worker string) any {
		return scopeRecord{Worker: worker, Type: string(e.AssetType()), Entry: raw, Admitted: admitted}
	})
}

// appendRecord appends a record of kind about what to the job's records,
// with the data data gives for this worker.
func (s *Scope) appendRecord(kind, what string, data func(worker string) any) {
	r := s.rep.Load()
	if r == nil {
		return
	}

	if _, err := r.topic.Append(kind, r.job, data(r.worker)); err != nil && s.Session != nil &&
		s.Session.Log() != nil {
		s.Session.Log().Warn("the "+kind+" record was not shared with the job's other workers",
			slog.String("asset", what), slog.String("error", err.Error()))
	}
}

// Apply takes the scope entries and admission decisions the job's other
// workers recorded among recs, the work topic's records in order. Records
// seen before may be given again.
func (s *Scope) Apply(recs []*dbt.JournalRecord) {
	r := s.rep.Load()
	if r == nil {
		return
	}

	var grew bool
	for _, rec := range recs {
		if rec.Key != r.job {
			continue
		}
		switch rec.Kind {
		case ScopeAddKind:
			var sr scopeRecord
			if err := json.Unmarshal(rec.Data, &sr); err != nil || sr.Worker == r.worker {
				continue
			}
			if e, err := decodeEntry(sr.Type, sr.Entry); err == nil && s.addEntry(e, sr.Admitted, false) {
				grew = true
			}
		case AdmissionKind:
			var ar admissionRecord
			if err := json.Unmarshal(rec.Data, &ar); err == nil && ar.Worker != r.worker {
				s.applyAdmission(&ar)
			}
		}
	}
	if grew {
		// cached standings are stale, and held assets may now be in
		go s.grown()
	}
}

// decodeEntry reads a scope entry of the asset type.
func decodeEntry(atype string, raw json.RawMessage) (oam.Asset, error) {
	a, err := client.ParseAsset(atype, raw)
	if err != nil {
		return nil, err
	}
	if entryOf(a) != a {
		return nil, fmt.Errorf("%s is not a scope entry", atype)
	}
	return a, nil
}
