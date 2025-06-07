package dns

import (
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	general "github.com/owasp-amass/open-asset-model/general"
)

// matchers defines patterns to detect services via TXT records
var matchers = map[string]string{
	"airtable-verification":          "Airtable",
	"aliyun-site-verification":       "Aliyun",
	"anodot-domain-verification":     "Anodot",
	"apperio-domain-verification":    "Apperio",
	"apple-domain-verification":      "Apple",
	"atlassian-domain-verification":  "Atlassian",
	"bugcrowd-verification":          "Bugcrowd",
	"canva-site-verification":        "Canva",
	"cisco-ci-domain-verification":   "Cisco",
	"cursor-domain-verification":     "Cursor",
	"docusign=":                       "Docusign",
	"dropbox-domain-verification":    "Dropbox",
	"facebook-domain-verification":   "Facebook",
	"globalsign-smime-dv":            "Globalsign",
	"google-site-verification":       "Google",
	"hubspot-developer-verification": "HubSpot",
	"knowbe4-site-verification":      "Knowbe4",
	"krisp-domain-verification":      "Krisp",
	"lastpass-verification-code":     "Lastpass",
	"mailru-verification":            "Mailru",
	"miro-verification":              "Miro",
	"mongodb-site-verification":      "MongoDB",
	"notion-domain-verification":     "Notion",
	"onetrust-domain-verification":   "OneTrust",
	"openai-domain-verification":     "OpenAI",
	"pendo-domain-verification":      "Pendo",
	"postman-domain-verification":    "Postman",
	"segment-site-verification":      "Segment",
	"status-page-domain-verification":"StatusPage",
	"stripe-verification":            "Stripe",
	"twilio-domain-verification":     "Twilio",
	"yahoo-verification-key":         "Yahoo",
	"yandex-verification":            "Yandex",
	"zoom-domain-verification":       "Zoom",
}

// txtServiceDiscovery is the core handler for TXT-based service discovery.
type txtServiceDiscovery struct {
	name   string
	source *et.Source
}

// check is invoked for each FQDN event to inspect TXT records.
func (t *txtServiceDiscovery) check(e *et.Event) error {
	if e == nil || e.Entity == nil {
		return nil
	}

	// The engine transforms FQDN assets into *dbt.Entity instances.
	host, ok := e.Entity.Asset.(*dbt.Entity)
	if !ok {
		return nil
	}

	// Determine cache TTL boundary
	since, err := support.TTLStartTime(e.Session.Config(), string(oamdns.FQDN{}), string(oamdns.FQDN{}), t.name)
	if err != nil {
		return err
	}

	// Gather TXT entries: live & cached
	var entries []string
	for _, rr := range support.Query(e.Session, host, dns.TypeTXT) {
		entries = append(entries, strings.Split(rr.String(), "\n")...)
	}
	for _, prop := range support.LoadDNSRecordProperties(e.Session, host, t.source, since) {
		entries = append(entries, prop.Value())
	}

	// Match patterns and build findings
	var findings []*support.Finding
	for _, txt := range entries {
		for pattern, svc := range matchers {
			if strings.Contains(txt, pattern) {
				findings = append(findings, &support.Finding{
					From:     host,
					FromName: host.Name,
					To:       host,
					ToName:   svc,
					ToMeta:   txt,
					Rel:      &general.SimpleRelation{Name: "TXT record"},
				})
			}
		}
	}

	// Emit the findings
	if len(findings) > 0 {
		support.ProcessAssetsWithSource(e, findings, t.source, t.name, t.name)
	}
	return nil
}
