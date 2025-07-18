// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"fmt"
	"log/slog"
	"strings"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type txtHandler struct {
	name   string
	source *et.Source
	plugin *dnsPlugin
}

func (r *txtHandler) check(e *et.Event) error {
	// Create context attributes for consistent logging
	attr := slog.Group("plugin", "name", r.plugin.name, "handler", r.name)

	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "FQDN", r.plugin.name)
	if err != nil {
		return err
	}

	var txtEntries []string
	if tags, err := e.Session.Cache().GetEntityTags(e.Entity, since, "dns_record"); err == nil {
		for _, tag := range tags {
			if prop, ok := tag.Property.(*oamdns.DNSRecordProperty); ok && prop.Header.RRType == int(dns.TypeTXT) {
				txtEntries = append(txtEntries, prop.Data)
			}
		}
	}

	for _, txt := range txtEntries {
		for prefix, org := range prefixes {
			if strings.Contains(txt, prefix) {
				e.Session.Log().Info(fmt.Sprintf("TXT record for domain verification: %s", org), attr)
				break
			}
		}
	}
	return nil
}

var prefixes = map[string]string{
	"adobe-idp-site-verification=":      "Adobe Inc.",
	"adobe-sign-verification=":          "Adobe Inc.",
	"ahrefs-site-verification_":         "Ahrefs Pte. Ltd.",
	"airtable-verification=":            "Formagrid, Inc.",
	"aliyun-site-verification=":         "Alibaba Cloud US LLC",
	"amazonses=":                        "Amazon Web Services, Inc.",
	"amazonses:":                        "Amazon Web Services, Inc.",
	"anodot-domain-verification=":       "Anodot Ltd",
	"apperio-domain-verification=":      "PERSUIT Operations Pty Ltd",
	"apple-domain-verification=":        "Apple Inc.",
	"asuid=":                            "Google LLC",
	"atlassian-domain-verification=":    "Atlassian Corporation Plc",
	"brave-ledger-verification=":        "Brave Software, Inc.",
	"bugcrowd-verification=":            "Bugcrowd Inc.",
	"canva-site-verification=":          "Canva LLC.",
	"ciscocidomainverification=":        "Cisco Systems, Inc.",
	"cisco-ci-domain-verification":      "Cisco Systems, Inc.",
	"citrix.mobile.ads.otp=":            "Citrix Systems, Inc.",
	"citrix-verification-code=":         "Citrix Systems, Inc.",
	"clickfunnels-domain-verification=": "Etison LLC",
	"cursor-domain-verification=":       "Anysphere Inc.",
	"detectify-verification=":           "Detectify AB",
	"docusign=":                         "DocuSign, Inc.",
	"drift-domain-verification=":        "Drift.com, Inc.",
	"dropbox-domain-verification=":      "Dropbox, Inc.",
	"DZC:":                              "GoDaddy.com, LLC",
	"Entrust:":                          "Entrust Corporation",
	"fastly-domain-delegation=":         "Fastly, Inc.",
	"facebook-domain-verification=":     "Meta Platforms, Inc.",
	"_globalsign-domain-verification=":  "GlobalSign, Inc.",
	"globalsign-domain-verification=":   "GlobalSign, Inc.",
	"globalsign-smime-dv=":              "GlobalSign, Inc.",
	"godaddyverification=":              "GoDaddy.com, LLC",
	"google-domain-verification=":       "Google LLC",
	"google-site-verification=":         "Google LLC",
	"have-i-been-pwned-verification=":   "Troy Hunt / Have I Been Pwned",
	"hubspot-developer-verification=":   "HubSpot, Inc.",
	"hubspot-site-verification=":        "HubSpot, Inc.",
	"knowbe4-site-verification=":        "KnowBe4, Inc.",
	"krisp-domain-verification=":        "Krisp Technologies, Inc.",
	"lastpass-verification-code=":       "LastPass US LP",
	"logmein-verification-code=":        "LogMeIn, Inc.",
	"mailchimp=":                        "Intuit Inc.",
	"mailru-verification=":              "VK Company Limited",
	"mailru-verification:":              "VK Company Limited",
	"miro-verification=":                "RealtimeBoard, Inc.",
	"mongodb-site-verification=":        "MongoDB, Inc.",
	"MS=":                               "Microsoft Corporation",
	"mscid=":                            "Microsoft Corporation",
	"nethely-dvc:":                      "Nethely Kft.",
	"netlify-verification=":             "Netlify, Inc.",
	"nifty-dns-verify:":                 "Fujitsu Limited",
	"notion-domain-verification=":       "Notion Labs, Inc.",
	"onetrust-domain-verification=":     "OneTrust LLC",
	"openai-domain-verification=":       "OpenAI, Inc.",
	"pardot_":                           "Salesforce.com, Inc.",
	"pardot-domain-verification=":       "Salesforce.com, Inc.",
	"pendo-domain-verification=":        "Pendo.io, Inc.",
	"postman-domain-verification=":      "Postman, Inc.",
	"Probe.ly:":                         "Probely, S.A",
	"protonmail-verification=":          "Proton AG",
	"sendinblue-code:":                  "Sendinblue SAS",
	"Sendinblue-code:":                  "Sendinblue SAS",
	"segment-domain-verification=":      "Twilio Inc.",
	"SFMC-":                             "ExactTarget, LLC",
	"shopify-verification-code=":        "Shopify Inc.",
	"slack-domain-verification=":        "Slack Technologies, LLC",
	"sophos-domain-verification=":       "Sophos Limited",
	"square-verification=":              "Block, Inc.",
	"status-page-domain-verification=":  "Atlassian Corporation Plc",
	"statuspage-domain-verification=":   "Atlassian Corporation Plc",
	"storiesonboard-verification=":      "DevMads Ltd.",
	"stripe-verification=":              "Stripe, Inc.",
	"teamviewer-sso-verification=":      "TeamViewer Germany GmbH",
	"tiktok-domain-verification=":       "TikTok Pte. Ltd.",
	"typeform-site-verification=":       "Typeform S.L.",
	"twilio-domain-verification=":       "Twilio Inc.",
	"upspin=":                           "Google LLC",
	"vercel-domain-verification=":       "Vercel Inc.",
	"webexdomainverification.":          "Cisco Systems, Inc.",
	"webexdomainverification=":          "Cisco Systems, Inc.",
	"webflow-verification=":             "Webflow, Inc.",
	"workplace-domain-verification=":    "Meta Platforms, Inc.",
	"yahoo-verification-key=":           "Yahoo! Inc.",
	"yandex-verification=":              "YANDEX LLC",
	"zoho-verification=":                "Zoho Corporation Pvt. Ltd.",
	"zoom-domain-verification":          "Zoom Communications, Inc.",
	"ZOOM_verify_":                      "Zoom Communications, Inc.",
}
