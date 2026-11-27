// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package edgar

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/plugintest"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oamfin "github.com/owasp-amass/open-asset-model/financial"
	"github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
	"golang.org/x/time/rate"
)

const exampleSubmissions = `{"cik":"0000320193","name":"Example Corp","phone":"(408) 996-1010",
  "addresses":{"business":{"street1":"1 Infinite Loop","city":"Cupertino","stateOrCountry":"CA","zipCode":"95014"}},
  "filings":{"recent":{
    "accessionNumber":["0000320193-24-000010","0000320193-24-000005","0000320193-23-000106"],
    "form":["D","8-K","10-K"],
    "filingDate":["2024-02-01","2024-01-15","2023-11-03"],
    "primaryDocument":["primary_doc.xml","x8k.htm","x10k.htm"]}}}`

const exampleIndex = `<html><body><table>
<tr><td>1</td><td>10-K</td><td><a href="/Archives/edgar/data/320193/000032019323000106/x10k.htm">x10k.htm</a></td><td>10-K</td><td>9</td></tr>
<tr><td>2</td><td>EX-21.1</td><td><a href="/Archives/edgar/data/320193/000032019323000106/ex21.htm">ex21.htm</a></td><td>EX-21.1</td><td>1</td></tr>
</table></body></html>`

const exampleExhibit = `<html><body><table>
<tr><td><b>Name of Subsidiary</b></td><td><b>Jurisdiction of Incorporation</b></td></tr>
<tr><td>Example Operations International Limited</td><td>Ireland</td></tr>
<tr><td>Example Sales, LLC</td><td>Delaware</td></tr>
</table></body></html>`

func TestFilingsCollectsTheRegistrant(t *testing.T) {
	sess := plugintest.NewSession(t)
	sess.TTL(60)

	var agents []string
	sec := func(body string) http.HandlerFunc {
		return func(w http.ResponseWriter, r *http.Request) {
			agents = append(agents, r.Header.Get("User-Agent"))
			_, _ = io.WriteString(w, body)
		}
	}
	web := sess.Web()
	web.Handle("GET www.sec.gov/files/company_tickers.json", sec(`{
	  "0":{"cik_str":320193,"ticker":"EXMP","title":"Example Corp."},
	  "1":{"cik_str":1,"ticker":"OTHR","title":"Other Holdings Inc"}}`))
	web.Handle("GET data.sec.gov/submissions/CIK0000320193.json", sec(exampleSubmissions))
	web.Handle("GET www.sec.gov/Archives/edgar/data/320193/000032019324000010/primary_doc.xml", sec(
		`<edgarSubmission><offeringData><offeringSalesAmounts><totalOfferingAmount>5000000</totalOfferingAmount>`+
			`<totalAmountSold>3500000</totalAmountSold></offeringSalesAmounts></offeringData></edgarSubmission>`))
	web.Handle("GET www.sec.gov/Archives/edgar/data/320193/000032019323000106/0000320193-23-000106-index.htm", sec(exampleIndex))
	web.Handle("GET www.sec.gov/Archives/edgar/data/320193/000032019323000106/ex21.htm", sec(exampleExhibit))

	ed := NewEDGAR().(*edgar)
	ed.rlimit = rate.NewLimiter(rate.Inf, 1)
	ed.log = slog.New(slog.NewTextHandler(io.Discard, nil))
	ed.filings = &filings{name: ed.name + "-Filings-Handler", plugin: ed}

	orgent := sess.Asset(t, &oamorg.Organization{ID: "example:test", Name: semantics.OrgNameKey("Example Corporation")})
	sess.Scope().Add(orgent.Asset)
	d := &plugintest.Dispatcher{}
	e := &et.Event{Entity: orgent, Session: sess, Dispatcher: d}
	if err := ed.filings.check(e); err != nil {
		t.Fatal(err)
	}

	for _, a := range agents {
		if a != userAgent {
			t.Errorf("a request was sent with the User-Agent %q", a)
		}
	}

	ctx := context.Background()
	var cik string
	if edges, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "id"); err == nil {
		for _, edge := range edges {
			if ent, err := sess.DB().FindEntityById(ctx, edge.ToEntity.ID); err == nil {
				if id, ok := ent.Asset.(*general.Identifier); ok && id.Type == CIKIdentifier {
					cik = id.ID
				}
			}
		}
	}
	if cik != "0000320193" {
		t.Fatalf("CIK = %q; requests %v", cik, sess.Web().Requests())
	}

	// The Form D's amount sold is received by the organization's account.
	recv := org.OrgTransfersReceived(sess, orgent, time.Now().Add(-time.Hour), ed.source)
	if len(recv) != 1 {
		t.Fatalf("transfers = %v", recv)
	}
	if f := recv[0].Asset.(*oamfin.FundsTransfer); f.ID != "secformd:0000320193-24-000010" || f.Amount != 3500000 {
		t.Errorf("transfer = %+v", f)
	}

	// The subsidiaries from the 10-K's Exhibit 21 are linked and dispatched,
	// and so is the business phone.
	subs, err := sess.DB().OutgoingEdges(ctx, orgent, time.Time{}, "subsidiary")
	if err != nil || len(subs) != 2 {
		t.Errorf("subsidiary edges = %v, %v", subs, err)
	}
	var orgs, phones int
	for _, ev := range d.Events() {
		switch ev.Entity.Asset.(type) {
		case *oamorg.Organization:
			orgs++
		default:
			if strings.HasPrefix(ev.Name, "+1") {
				phones++
			}
		}
	}
	if orgs != 2 || phones != 1 {
		t.Errorf("dispatched %v", d.Names())
	}

	// The ticker list is fetched once, and the organization is not looked
	// up again within the TTL.
	sent := len(sess.Web().Requests())
	if err := ed.filings.check(e); err != nil {
		t.Fatal(err)
	}
	other := sess.Asset(t, &oamorg.Organization{ID: "other:test", Name: "unknown"})
	sess.Scope().Add(other.Asset)
	if err := ed.filings.check(&et.Event{Entity: other, Session: sess, Dispatcher: d}); err != nil {
		t.Fatal(err)
	}
	if len(sess.Web().Requests()) != sent {
		t.Errorf("requests after the first check: %v", sess.Web().Requests()[sent:])
	}
}
