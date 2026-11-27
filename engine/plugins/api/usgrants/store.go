// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package usgrants

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amasshttp "github.com/owasp-amass/amass/v5/internal/net/http"
	dbt "github.com/owasp-amass/asset-db/types"
)

// grant is one award normalized across the three APIs before it is stored.
type grant struct {
	id, date, agency, recipient string
	amount                      float64
	// uei and duns identify the recipient, when the source gives them.
	uei, duns string
}

func (h *source) get(e *et.Event, u string) (string, error) {
	return h.request(e, &amasshttp.Request{URL: u})
}

func (h *source) postJSON(e *et.Event, u, body string) (string, error) {
	return h.request(e, &amasshttp.Request{
		URL:    u,
		Method: "POST",
		Header: amasshttp.Header{"Content-Type": []string{"application/json"}},
		Body:   body,
	})
}

func (h *source) request(e *et.Event, r *amasshttp.Request) (string, error) {
	_ = support.WaitLimit(e.Session.Ctx(), h.rlimit)
	e.Session.NetSem().Acquire()
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 30*time.Second)
	resp, err := amasshttp.RequestWebPage(ctx, e.Session.Clients().General, r)
	e.Session.NetSem().Release()
	cancel()
	if err != nil {
		return "", err
	}
	if resp.StatusCode != 200 {
		return "", fmt.Errorf("status %s", resp.Status)
	}
	if resp.Body == "" {
		return "", errors.New("empty body")
	}
	return resp.Body, nil
}

// store writes a matched grant as a FundsTransfer received by the organization,
// with the funding agency as the third_party funder.
func (h *source) store(e *et.Event, orgent *dbt.Entity, g *grant) *dbt.Entity {
	fundent := org.StoreReceivedTransfer(e, orgent, org.ReceivedTransfer{
		ID: g.id, Reference: g.id, Amount: g.amount, Date: g.date, Funder: g.agency,
	}, h.src)
	if fundent != nil {
		org.DispatchTransfers(e, fundent)
	}
	return fundent
}
