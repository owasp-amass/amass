// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"slices"
	"strings"

	"github.com/owasp-amass/amass/v5/engine/plugins/adstxt"
	"github.com/owasp-amass/amass/v5/engine/plugins/api"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/aviato"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/censys"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/edgar"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/fofa"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/gleif"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/ocds"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/osm"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/peeringdb"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/propublica"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/schemaorg"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/shodan"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/ted"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/usaspending"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/usgrants"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/wikidata"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/zoomeye"
	"github.com/owasp-amass/amass/v5/engine/plugins/archive"
	"github.com/owasp-amass/amass/v5/engine/plugins/attribution"
	"github.com/owasp-amass/amass/v5/engine/plugins/bimi"
	"github.com/owasp-amass/amass/v5/engine/plugins/bounty"
	"github.com/owasp-amass/amass/v5/engine/plugins/breach"
	"github.com/owasp-amass/amass/v5/engine/plugins/brute"
	"github.com/owasp-amass/amass/v5/engine/plugins/bucket"
	"github.com/owasp-amass/amass/v5/engine/plugins/cloud"
	"github.com/owasp-amass/amass/v5/engine/plugins/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/documents"
	"github.com/owasp-amass/amass/v5/engine/plugins/enrich"
	"github.com/owasp-amass/amass/v5/engine/plugins/horizontals"
	"github.com/owasp-amass/amass/v5/engine/plugins/identity"
	"github.com/owasp-amass/amass/v5/engine/plugins/lookalike"
	mtasts "github.com/owasp-amass/amass/v5/engine/plugins/mta_sts"
	"github.com/owasp-amass/amass/v5/engine/plugins/packages"
	"github.com/owasp-amass/amass/v5/engine/plugins/routing"
	"github.com/owasp-amass/amass/v5/engine/plugins/scrape"
	securitytxt "github.com/owasp-amass/amass/v5/engine/plugins/security_txt"
	bannerp "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/banner_probes"
	dnssd "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/dns"
	hp "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/http_probes"
	sshp "github.com/owasp-amass/amass/v5/engine/plugins/service_discovery/ssh_probes"
	"github.com/owasp-amass/amass/v5/engine/plugins/whois"
	"github.com/owasp-amass/amass/v5/engine/plugins/whois/bgptools"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

var pluginNewFuncs = []func() et.Plugin{
	api.NewAnubis,
	api.NewBinaryEdge,
	api.NewCertSpotter,
	api.NewChaos,
	api.NewColumbus,
	api.NewCrtsh,
	api.NewCrtshOrg,
	api.NewDNSRepo,
	api.NewGrepApp,
	api.NewHackerTarget,
	//api.NewHunterIO,
	api.NewLeakIX,
	api.NewPassiveTotal,
	api.NewProspeo,
	api.NewSecurityTrails,
	api.NewTeamCymru,
	api.NewThreatMiner,
	//api.NewURLScan,
	api.NewVirusTotal,
	api.NewZetalytics,
	archive.NewWayback,
	archive.NewCommonCrawl,
	documents.NewDocuments,
	attribution.NewAttribution,
	aviato.NewAviato,
	bgptools.NewBGPTools,
	breach.NewBreachExposure,
	bucket.NewBucketProbe,
	brute.NewFQDNAlterations,
	cloud.NewCloudRanges,
	dns.NewDNS,
	edgar.NewEDGAR,
	dnssd.NewDNSPlugin,
	enrich.NewBannerURLs,
	enrich.NewContacts,
	enrich.NewEmails,
	enrich.NewHeaderRefs,
	enrich.NewOnionLocation,
	enrich.NewPhoneDetails,
	enrich.NewTLSCerts,
	enrich.NewURLs,
	gleif.NewGLEIF,
	horizontals.NewHorizontals,
	hp.NewHTTPProbing,
	identity.NewIdentity,
	lookalike.NewLookalikes,
	mtasts.NewMTASTS,
	ocds.NewOCDS,
	osm.NewOpenStreetMap,
	peeringdb.NewPeeringDB,
	propublica.NewProPublica,
	securitytxt.NewSecurityTxt,
	bimi.NewBIMI,
	adstxt.NewAdsTxt,
	bounty.NewBountyScopes,
	packages.NewPackages,
	sshp.NewSSHProbing,
	bannerp.NewBannerProbing,
	rdap.NewRDAP,
	routing.NewRoutingRecords,
	wikidata.NewWikidata,
	schemaorg.NewSchemaOrg,
	shodan.NewShodan,
	censys.NewCensys,
	fofa.NewFOFA,
	zoomeye.NewZoomEye,
	scrape.NewBing,
	scrape.NewDNSHistory,
	scrape.NewDuckDuckGo,
	scrape.NewIPVerse,
	scrape.NewRapidDNS,
	scrape.NewSiteDossier,
	ted.NewTED,
	usaspending.NewUSASpending,
	usgrants.NewNSF,
	usgrants.NewNIH,
	usgrants.NewSBIR,
	whois.NewWHOIS,
	NewIPNetblock,
	NewJARMFingerprints,
	NewKnownFQDN,
}

// PluginNames returns the names of the engine's plugins, which include its
// data sources, sorted without regard to case. The plugins are created but
// not started.
func PluginNames() []string {
	var names []string
	for _, f := range pluginNewFuncs {
		if p := f(); p != nil && p.Name() != "" {
			names = append(names, p.Name())
		}
	}

	slices.SortFunc(names, func(a, b string) int { return strings.Compare(strings.ToLower(a), strings.ToLower(b)) })
	return slices.Compact(names)
}

func LoadAndStartPlugins(r et.Registry) error {
	var started []et.Plugin

	for _, f := range pluginNewFuncs {
		if p := f(); p != nil {
			if err := p.Start(r); err != nil {
				stopPlugins(started)
				return err
			}

			started = append(started, p)
		}
	}

	return nil
}

func stopPlugins(started []et.Plugin) {
	for _, p := range started {
		p.Stop()
	}
}
