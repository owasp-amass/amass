// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package dns

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/miekg/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	"github.com/owasp-amass/amass/v5/engine/plugins/support/org"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
	oamgen "github.com/owasp-amass/open-asset-model/general"
	oamorg "github.com/owasp-amass/open-asset-model/org"
)

type txtHandler struct {
	name   string
	source *et.Source
	plugin *dnsPlugin
}

func (r *txtHandler) check(e *et.Event) error {
	since, err := support.TTLStartTime(e.Session.Config(), "FQDN", "Organization", r.plugin.name)
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

	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	if tags, err := e.Session.DB().FindEntityTags(ctx, e.Entity, since, "dns_record"); err == nil {
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
		for prefix, oasset := range prefixes {
			if !strings.HasPrefix(txt, prefix) {
				continue
			}

			orgent, err := org.CreateOrgAsset(e.Session, e.Entity,
				&oamgen.SimpleRelation{Name: "verified_for"}, oasset, r.plugin.source)
			if err == nil && orgent != nil {
				orgs = append(orgs, orgent)
				fqdn := e.Entity.Asset.(*oamdns.FQDN).Name
				e.Session.Log().Info(fmt.Sprintf("%s has a site verification record for %s: %s",
					fqdn, oasset.Name, txt), slog.Group("plugin", "name", r.plugin.name, "handler", r.name))
			}
			break
		}
	}

	return orgs
}

func (r *txtHandler) process(e *et.Event, entities []*dbt.Entity) {
	for _, entity := range entities {
		if o, ok := entity.Asset.(*oamorg.Organization); ok && o != nil {
			_ = e.Dispatcher.DispatchEvent(&et.Event{
				Name:    o.Name,
				Entity:  entity,
				Session: e.Session,
			})
		}
	}
}

var prefixes = map[string]*oamorg.Organization{
	"adobe-idp-site-verification=":      {Name: "Adobe Inc.", Jurisdiction: "US-DE", RegistrationID: "2748129"},
	"adobe-sign-verification=":          {Name: "Adobe Inc.", Jurisdiction: "US-DE", RegistrationID: "2748129"},
	"ahrefs-site-verification_":         {Name: "Ahrefs Pte. Ltd.", Jurisdiction: "SG", RegistrationID: "201227417H"},
	"airtable-verification=":            {Name: "Formagrid, Inc.", Jurisdiction: "US-DE", RegistrationID: "5288358"},
	"aliyun-site-verification=":         {Name: "Alibaba Cloud US LLC", Jurisdiction: "US-DE", RegistrationID: "6219156"},
	"amazonses=":                        {Name: "Amazon Web Services, Inc.", Jurisdiction: "US-DE", RegistrationID: "4152954"},
	"amazonses:":                        {Name: "Amazon Web Services, Inc.", Jurisdiction: "US-DE", RegistrationID: "4152954"},
	"anodot-domain-verification=":       {Name: "Anodot Ltd", Jurisdiction: "IL", RegistrationID: "515072825"},
	"anthropic-domain-verification-":    {Name: "Anthropic, PBC", Jurisdiction: "US-DE", RegistrationID: "4860621"},
	"apperio-domain-verification=":      {Name: "PERSUIT Operations Pty Ltd", Jurisdiction: "AU", RegistrationID: "610419700"},
	"apple-domain-verification=":        {Name: "Apple Inc.", Jurisdiction: "US-CA", RegistrationID: "806592"},
	"asuid=":                            {Name: "Google LLC", Jurisdiction: "US-DE", RegistrationID: "3582691"},
	"atlassian-domain-verification=":    {Name: "Atlassian Corporation Plc", Jurisdiction: "GB", RegistrationID: "08776021"},
	"brave-ledger-verification=":        {Name: "Brave Software, Inc.", Jurisdiction: "US-DE", RegistrationID: "5548045"},
	"bugcrowd-verification=":            {Name: "Bugcrowd Inc.", Jurisdiction: "US-DE", RegistrationID: "5284241"},
	"canva-site-verification=":          {Name: "CANVA PTY LTD", Jurisdiction: "AU", RegistrationID: "158929938"},
	"ciscocidomainverification=":        {Name: "Cisco Systems, Inc.", Jurisdiction: "US-DE", RegistrationID: "3704171"},
	"cisco-ci-domain-verification":      {Name: "Cisco Systems, Inc.", Jurisdiction: "US-DE", RegistrationID: "3704171"},
	"citrix.mobile.ads.otp=":            {Name: "Citrix Systems, Inc.", Jurisdiction: "US-DE", RegistrationID: "2193573"},
	"citrix-verification-code=":         {Name: "Citrix Systems, Inc.", Jurisdiction: "US-DE", RegistrationID: "2193573"},
	"clickfunnels-domain-verification=": {Name: "Etison LLC", Jurisdiction: "US-ID", RegistrationID: "W135940"},
	"cursor-domain-verification=":       {Name: "Anysphere Inc.", Jurisdiction: "US-DE", RegistrationID: "6564202"},
	"detectify-verification=":           {Name: "Detectify AB", Jurisdiction: "SE", RegistrationID: "5569859084"},
	"docusign=":                         {Name: "DocuSign, Inc.", Jurisdiction: "US-DE", RegistrationID: "5193721"},
	"drift-domain-verification=":        {Name: "Drift.com, Inc.", Jurisdiction: "US-DE", RegistrationID: "5703816"},
	"dropbox-domain-verification=":      {Name: "Dropbox, Inc.", Jurisdiction: "US-DE", RegistrationID: "4348296"},
	"DZC:":                              {Name: "GoDaddy.com, LLC", Jurisdiction: "US-DE", RegistrationID: "5074703"},
	"Entrust:":                          {Name: "Entrust Corporation", Jurisdiction: "US-DE", RegistrationID: "705421"},
	"fastly-domain-delegation=":         {Name: "Fastly, Inc.", Jurisdiction: "US-DE", RegistrationID: "4947714"},
	"facebook-domain-verification=":     {Name: "Meta Platforms, Inc.", Jurisdiction: "US-DE", RegistrationID: "3835815"},
	"fireflies-verification=":           {Name: "Fireflies.AI Corp.", Jurisdiction: "US-DE", RegistrationID: "6201865"},
	"_globalsign-domain-verification=":  {Name: "GlobalSign, Inc.", Jurisdiction: "US-NH", RegistrationID: "578611"},
	"globalsign-domain-verification=":   {Name: "GlobalSign, Inc.", Jurisdiction: "US-NH", RegistrationID: "578611"},
	"globalsign-smime-dv=":              {Name: "GlobalSign, Inc.", Jurisdiction: "US-NH", RegistrationID: "578611"},
	"godaddyverification=":              {Name: "GoDaddy.com, LLC", Jurisdiction: "US-DE", RegistrationID: "5074703"},
	"google-domain-verification=":       {Name: "Google LLC", Jurisdiction: "US-DE", RegistrationID: "3582691"},
	"google-site-verification=":         {Name: "Google LLC", Jurisdiction: "US-DE", RegistrationID: "3582691"},
	"have-i-been-pwned-verification=":   {Name: "Have I Been Pwned", Jurisdiction: "AU", RegistrationID: "62085442020"},
	"hubspot-developer-verification=":   {Name: "HubSpot, Inc.", Jurisdiction: "US-DE", RegistrationID: "3950045"},
	"hubspot-site-verification=":        {Name: "HubSpot, Inc.", Jurisdiction: "US-DE", RegistrationID: "3950045"},
	"knowbe4-site-verification=":        {Name: "KnowBe4, Inc.", Jurisdiction: "US-DE", RegistrationID: "4858473"},
	"krisp-domain-verification=":        {Name: "Krisp Technologies, Inc.", Jurisdiction: "US-DE", RegistrationID: "6543638"},
	"lastpass-verification-code=":       {Name: "LastPass US LP", Jurisdiction: "US-DE", RegistrationID: "6402861"},
	"logmein-verification-code=":        {Name: "LogMeIn, Inc.", Jurisdiction: "US-DE", RegistrationID: "3830661"},
	"mailchimp=":                        {Name: "Intuit Inc.", Jurisdiction: "US-DE", RegistrationID: "2324451"},
	"mailru-verification=":              {Name: "VK Company Limited", Jurisdiction: "RU", RegistrationID: "1233900010065"},
	"mailru-verification:":              {Name: "VK Company Limited", Jurisdiction: "RU", RegistrationID: "1233900010065"},
	"miro-verification=":                {Name: "RealtimeBoard, Inc.", Jurisdiction: "US-DE", RegistrationID: "6438916"},
	"mongodb-site-verification=":        {Name: "MongoDB, Inc.", Jurisdiction: "US-DE", RegistrationID: "4462691"},
	"MS=":                               {Name: "Microsoft Corporation", Jurisdiction: "US-WA", RegistrationID: "600413485"},
	"mscid=":                            {Name: "Microsoft Corporation", Jurisdiction: "US-WA", RegistrationID: "600413485"},
	"nethely-dvc:":                      {Name: "Nethely Kft.", Jurisdiction: "HU", RegistrationID: "0109961790"},
	"netlify-verification=":             {Name: "Netlify, Inc.", Jurisdiction: "US-DE", RegistrationID: "5484838"},
	"nifty-dns-verify:":                 {Name: "Fujitsu Limited", Jurisdiction: "JP", RegistrationID: "1020001071491"},
	"notion-domain-verification=":       {Name: "Notion Labs, Inc.", Jurisdiction: "US-DE", RegistrationID: "5171120"},
	"onetrust-domain-verification=":     {Name: "OneTrust LLC", Jurisdiction: "US-DE", RegistrationID: "6044234"},
	"openai-domain-verification=":       {Name: "OpenAI Foundation", Jurisdiction: "US-DE", RegistrationID: "5883832"},
	"pardot_":                           {Name: "Salesforce.com, Inc.", Jurisdiction: "US-DE", RegistrationID: "2991326"},
	"pardot-domain-verification=":       {Name: "Salesforce.com, Inc.", Jurisdiction: "US-DE", RegistrationID: "2991326"},
	"pendo-domain-verification=":        {Name: "Pendo.io, Inc.", Jurisdiction: "US-DE", RegistrationID: "5387913"},
	"postman-domain-verification=":      {Name: "Postman, Inc.", Jurisdiction: "US-DE", RegistrationID: "5814450"},
	"Probe.ly:":                         {Name: "Probely, S.A", Jurisdiction: "PT", RegistrationID: "514413735"},
	"protonmail-verification=":          {Name: "Proton AG", Jurisdiction: "CH", RegistrationID: "CHE354686492"},
	"sendinblue-code:":                  {Name: "Sendinblue SAS", Jurisdiction: "FR", RegistrationID: "49801929800065"},
	"Sendinblue-code:":                  {Name: "Sendinblue SAS", Jurisdiction: "FR", RegistrationID: "49801929800065"},
	"segment-domain-verification=":      {Name: "Twilio Inc.", Jurisdiction: "US-DE", RegistrationID: "4518652"},
	"SFMC-":                             {Name: "ExactTarget, LLC", Jurisdiction: "US-DE", RegistrationID: "4807289"},
	"shopify-verification-code=":        {Name: "Shopify Inc.", Jurisdiction: "CA-ON", RegistrationID: "4261607"},
	"slack-domain-verification=":        {Name: "Slack Technologies, LLC", Jurisdiction: "US-DE", RegistrationID: "4681604"},
	"sophos-domain-verification=":       {Name: "Sophos Limited", Jurisdiction: "GB", RegistrationID: "02096520"},
	"square-verification=":              {Name: "Block, Inc.", Jurisdiction: "US-DE", RegistrationID: "4699855"},
	"status-page-domain-verification=":  {Name: "Atlassian Corporation Plc", Jurisdiction: "GB", RegistrationID: "08776021"},
	"statuspage-domain-verification=":   {Name: "Atlassian Corporation Plc", Jurisdiction: "GB", RegistrationID: "08776021"},
	"storiesonboard-verification=":      {Name: "DevMads Ltd.", Jurisdiction: "HU", RegistrationID: "0209079737"},
	"stripe-verification=":              {Name: "Stripe, LLC.", Jurisdiction: "US-DE", RegistrationID: "4675506"},
	"teamviewer-sso-verification=":      {Name: "TeamViewer Germany GmbH", Jurisdiction: "DE", RegistrationID: "HRB534075"},
	"tiktok-domain-verification=":       {Name: "TikTok Pte. Ltd.", Jurisdiction: "SG", RegistrationID: "201719908M"},
	"typeform-site-verification=":       {Name: "Typeform S.L.", Jurisdiction: "ES", RegistrationID: "B65831836"},
	"twilio-domain-verification=":       {Name: "Twilio Inc.", Jurisdiction: "US-DE", RegistrationID: "4518652"},
	"upspin=":                           {Name: "Google LLC", Jurisdiction: "US-DE", RegistrationID: "3582691"},
	"vercel-domain-verification=":       {Name: "Vercel Inc.", Jurisdiction: "US-DE", RegistrationID: "4855562"},
	"webexdomainverification.":          {Name: "Cisco Systems, Inc.", Jurisdiction: "US-DE", RegistrationID: "3704171"},
	"webexdomainverification=":          {Name: "Cisco Systems, Inc.", Jurisdiction: "US-DE", RegistrationID: "3704171"},
	"webflow-verification=":             {Name: "Webflow, Inc.", Jurisdiction: "US-DE", RegistrationID: "5218730"},
	"workplace-domain-verification=":    {Name: "Meta Platforms, Inc.", Jurisdiction: "US-DE", RegistrationID: "3835815"},
	"yahoo-verification-key=":           {Name: "Yahoo! Inc.", Jurisdiction: "US-DE", RegistrationID: "7289895"},
	"yandex-verification=":              {Name: "YANDEX LLC", Jurisdiction: "RU", RegistrationID: "1027700229193"},
	"zoho-verification=":                {Name: "Zoho Corporation Pvt. Ltd.", Jurisdiction: "IN", RegistrationID: "U40100TN2010PTC075961"},
	"zoom-domain-verification":          {Name: "Zoom Communications, Inc.", Jurisdiction: "US-DE", RegistrationID: "4969967"},
	"ZOOM_verify_":                      {Name: "Zoom Communications, Inc.", Jurisdiction: "US-DE", RegistrationID: "4969967"},
}
