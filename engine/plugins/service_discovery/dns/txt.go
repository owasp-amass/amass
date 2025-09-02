// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	"github.com/owasp-amass/open-asset-model/general"
	"github.com/owasp-amass/open-asset-model/org"
)

type txtHandler struct {
	name   string
	source *et.Source
	plugin *dnsPlugin
}

func (r *txtHandler) check(e *et.Event) error {
	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", r.plugin.name)
	if err != nil {
		return err
	}

	if orgs := r.store(e, r.lookup(e, since)); len(orgs) > 0 {
		r.process(e, orgs)
	}
	return nil
}

func (r *txtHandler) lookup(e *et.Event, since time.Time) []string {
	var rdata []string

	if tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record"); err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
				rdata = append(rdata, prop.Data)
			}
		}
	}

	return rdata
}

func (r *txtHandler) store(e *et.Event, records []string) []*dbt.Entity {
	var orgs []*dbt.Entity

	for _, txt := range records {
		for prefix, name := range prefixes {
			if !strings.HasPrefix(txt, prefix) {
				continue
			}

			o, err := support.CreateOrgAsset(e.Session, e.Entity,
				&general.SimpleRelation{Name: "verified_for"},
				&org.Organization{Name: name}, r.plugin.source)

			if err == nil && o != nil {
				orgs = append(orgs, o)
				fqdn := e.Entity.Asset.(*oamdns.FQDN).Name
				e.Session.Log().Info(fmt.Sprintf("%s has a site verification record for %s: %s",
					fqdn, name, txt), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
			}
			break
		}
	}

	return orgs
}

func (r *txtHandler) process(e *et.Event, entities []*dbt.Entity) {
	for _, entity := range entities {
		if o, ok := entity.Asset.(*org.Organization); ok && o != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    o.Name,
				Entity:  entity,
				Session: e.Session,
			})
		}
	}
}

var prefixes = map[string]string{
	"_acme-challenge.":                       "Let’s Encrypt",
	"_globalsign-domain-verification=":  "GlobalSign, Inc.",
	"_netlock=":                              "NetLock Kft.",
	"_telesec-domain-validation=":            "T-Systems International GmbH",
	"Acumbamail-domain-verification=":        "Acumbamail S.L.",
	"adobe-idp-site-verification=":      "Adobe Inc.",
	"adobe-sign-verification=":          "Adobe Inc.",
	"adstxt-domain-verification=":            "ionix Ltd",
	"ahrefs-site-verification_":         "Ahrefs Pte. Ltd.",
	"airtable-verification=":            "Formagrid, Inc.",
	"aliyun-site-verification=":         "Alibaba Cloud US LLC",
	"amazonses:":                        "Amazon Web Services, Inc.",
	"amazonses=":                        "Amazon Web Services, Inc.",
	"android-enroll=":                        "Ivanti Inc.", // this seems counterintuitive
	"android-mdm-enroll=":                    "Ivanti Inc.", // // this seems counterintuitive
	"anodot-domain-verification=":       "Anodot Ltd",
	"apperio-domain-verification=":      "PERSUIT Operations Pty Ltd",
	"apple-domain-verification=":        "Apple Inc.",
	"asuid=":                            "Google LLC",
	"atlassian-domain-verification=":    "Atlassian Corporation Plc",
	"beam-verification=":                     "Suitable Technologies, Inc.",
	"blitz=":                                 "FeedBlitz LLC",
	"botify-site-verification=":              "Botify SAS",
	"brave-ledger-verification=":        "Brave Software, Inc.",
	"bugcrowd-verification=":            "Bugcrowd Inc.",
	"bvm-site-verification=":                 "Barracuda Networks, Inc.",
	"canva-site-verification=":          "Canva LLC.",
	"cisco-ci-domain-verification":      "Cisco Systems, Inc.",
	"cisco-ci-domain-verification=":          "Cisco Systems, Inc.",
	"cisco-site-verification=":               "Cisco Systems, Inc.",
	"ciscocidomainverification=":        "Cisco Systems, Inc.",
	"citrix-verification-code=":         "Citrix Systems, Inc.",
	"citrix.mobile.ads.otp=":            "Citrix Systems, Inc.",
	"clickfunnels-domain-verification=": "Etison LLC",
	"cloudbees-domain-verification:":         "CloudBees Inc.",
	"cloudControl-verification:":             "cloudControl GmbH",
	"cloudflare-verify":                      "Cloudflare Inc.",
	"cloudpiercer-verification=":             "Akamai Technologies, Inc.",
	"cursor-domain-verification=":       "Anysphere Inc.",
	"dailymotion-domain-verification=":       "Dailymotion SA",
	"daum-verification:":                     "Daum Communications Corporation",
	"detectify-verification=":                "Detectify AB",
	"Digicert=":                              "DigiCert Inc.",
	"digitalpoint-site-verify:":              "Digital Point Solutions, Inc.",
	"docker-verification=":                 "Docker, Inc.",
	"docusign=":                         "DocuSign, Inc.",
	"drift-domain-verification=":             "Drift.com, Inc.",
	"dropbox-domain-verification=":      "Dropbox, Inc.",
	"Dynatrace-site-verification=":           "Dynatrace, Inc.",
	"DZC:":                              "GoDaddy.com, LLC",
	"e2ma-verification:":                     "EMMA, INC.",
	"Entrust:":                          "Entrust Corporation",
	"facebook-domain-verification=":     "Meta Platforms, Inc.",
	"fastly-domain-delegation-":              "Fastly Inc.",
	"fastly-domain-delegation=":         "Fastly, Inc.",
	"favro-verification=":                    "Favro AB",
	"firebase=":                              "Google LLC",
	"fortifi-domain-verification=":           "Fortifi Ltd.",
	"github-verification=":                   "GitHub Inc.",
	"globalsign-domain-verification=":   "GlobalSign, Inc.",
	"globalsign-smime-dv=":              "GlobalSign, Inc.",
	"godaddyverification=":              "GoDaddy.com, LLC",
	"google-domain-verification=":       "Google LLC",
	"google-site-verification=":         "Google LLC",
	"have-i-been-pwned-verification=":   "Troy Hunt / Have I Been Pwned",
	"heroku-domain-verification=":            "Heroku (Salesforce)",
	"http://www.bhosted.nl:":                 "bHosted.nl",
	"hubspot-developer-verification=":   "HubSpot, Inc.",
	"hubspot-site-verification=":        "HubSpot, Inc.",
	"intacct-esk=":                           "The Sage Group plc",
	"inumbo-verification=":                   "Inumbo Ltd.",
	"iOS-enroll":                             "Ivanti Inc.", // seems very generic should we add this?
	"keybase-site-verification=":             "Keybase Inc.",
	"knowbe4-site-verification=":        "KnowBe4, Inc.",
	"krisp-domain-verification=":        "Krisp Technologies, Inc.",
	"lastpass-verification-code=":       "LastPass US LP",
	"LDLAUNCHPAD=":                           "LaunchPad Cloud",
	"loaderio=":                              "Loader.io",
	"loadmill-challenge=":                    "Loadmill Ltd",
	"logmein-domain-confirmation":            "GoTo Technologies USA, Inc.",
	"logmein-verification-code=":        "LogMeIn, Inc.",
	"loom-site-verification=":				"Loom, Inc.",
	"mailchimp=":                        "Intuit Inc.",
	"mailigen-site-verification=":            "Mailigen, SIA",
	"mailjet-domain-validation=":             "Mailjet SAS",
	"mailru-verification":              "VK Company Limited",
	"mailru-verification=":              "VK Company Limited",
	"miro-verification=":                "RealtimeBoard, Inc.",
	"mongodb-site-verification=":        "MongoDB, Inc.",
	"MS=":                               "Microsoft Corporation",
	"mscid=":                            "Microsoft Corporation",
	"mtc=":                                   "Microsoft Corporation",
	"nethely-dvc:":                      "Nethely Kft.",
	"netlify-verification=":             "Netlify, Inc.",
	"nifty-dns-verify:":                 "Fujitsu Limited",
	"notion-domain-verification=":       "Notion Labs, Inc.",
	"onetrust-domain-verification=":     "OneTrust LLC",
	"openai-domain-verification=":       "OpenAI, Inc.",
	"openstat-verification=":                 "Openstat",
	"OSIAGENTREGURL=":                        "Broadcom Inc.",
	"OSSRH-":                                 "Sonatype Inc.",
	"ostrio-domain:":                         "OSTR LTD",
	"pardot_":                           "Salesforce.com, Inc.",
	"pardot-domain-verification=":       "Salesforce.com, Inc.",
	"pendo-domain-verification=":        "Pendo.io, Inc.",
	"perlu-site-verification=":               "Perlu LLC",
	"postman-domain-verification=":      "Postman, Inc.",
	"Probe.ly:":                         "Probely, S.A",
	"protonmail-verification=":          "Proton AG",
	"QuoVadis=":                              "DigiCert, Inc.",
	"reachdesk-verification=": 	         "Reachdesk Ltd",
	"rebelmouse=":                            "RebelMouse Inc.",
	"ReleaseWLIDNamespace":                   "Microsoft Corporation",
	"segment-domain-verification=":      "Twilio Inc.",
	"segment-site-verification=":             "Segment, Inc.",
	"sendinblue-code:":                  "Sendinblue SAS",
	"Sendinblue-code:":                  "Sendinblue SAS",
	"SFMC-":                             "ExactTarget, LLC",
	"shopify-verification-code=":        "Shopify Inc.",
	"site24x7-domain-verification=":          "Zoho Corporation",
	"slack-domain-verification=":        "Slack Technologies, LLC",
	"smartsheet-site-validation=":            "Smartsheet Inc.",
	"sonatype=":                              "Sonatype Inc.",
	"sophos-domain-verification=":       "Sophos Limited",
	"spycloud-domain-verification=":          "SpyCloud, Inc.",
	"square-verification=":              "Block, Inc.",
	"status-page-domain-verification=":  "Atlassian Corporation Plc",
	"statuspage-domain-verification=":   "Atlassian Corporation Plc",
	"storiesonboard-verification=":      "DevMads Ltd.",
	"stripe-verification=":              "Stripe, Inc.",
	"swisssign-check=":                       "SwissSign AG",
	"teamviewer-sso-verification=":      "TeamViewer Germany GmbH",
	"thousandeyes:":                          "ThousandEyes Inc.",
	"tiktok-domain-verification=":       "TikTok Pte. Ltd.",
	"tinfoil-site-verification:":             "Tinfoil Security, Inc.",
	"twilio-domain-verification=":       "Twilio Inc.",
	"typeform-site-verification=":       "Typeform S.L.",
	"ulogin-verification:":                   "Electronic Arts Inc.",
	"upspin=":                           "Google LLC",
	"uwsgi:":                                 "uWSGI", // open source repo - belongs to an individual instead of an org - shall we remove?
	"vercel-domain-verification=":       "Vercel Inc.",
	"webexdomainverification.":          "Cisco Systems, Inc.",
	"webexdomainverification=":          "Cisco Systems, Inc.",
	"webflow-verification=":             "Webflow, Inc.",
	"wiz-domain-verification=":           "Wiz, Inc.",
	"wmail-verification:":                    "Bookry Ltd",
	"workplace-domain-verification=":    "Meta Platforms, Inc.",
	"worksmobile-certification=":             "LINE WORKS Corporation",
	"wrike-verification=":                    "Wrike, Inc.",
	"yahoo-verification-key=":           "Yahoo! Inc.",
	"yandex-verification=":              "YANDEX LLC",
	"zapier-domain-verification-challenge=":  "Zapier Inc.",
	"zendeskverification=":                   "Zendesk Inc.",
	"zoho-verification=":                "Zoho Corporation Pvt. Ltd.",
	"ZOOM_verify_":                      "Zoom Communications, Inc.",
	"zoom-domain-verification":          "Zoom Communications, Inc.",
}