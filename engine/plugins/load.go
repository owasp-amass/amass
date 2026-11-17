// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/owasp-amass/amass/v5/engine/plugins/api"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/aviato"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/edgar"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/gleif"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/osm"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/rdap"
	"github.com/owasp-amass/amass/v5/engine/plugins/api/usaspending"
	"github.com/owasp-amass/amass/v5/engine/plugins/archive"
	"github.com/owasp-amass/amass/v5/engine/plugins/attribution"
	"github.com/owasp-amass/amass/v5/engine/plugins/breach"
	"github.com/owasp-amass/amass/v5/engine/plugins/brute"
	"github.com/owasp-amass/amass/v5/engine/plugins/cloud"
	"github.com/owasp-amass/amass/v5/engine/plugins/dns"
	"github.com/owasp-amass/amass/v5/engine/plugins/enrich"
	"github.com/owasp-amass/amass/v5/engine/plugins/horizontals"
	"github.com/owasp-amass/amass/v5/engine/plugins/lookalike"
	mtasts "github.com/owasp-amass/amass/v5/engine/plugins/mta_sts"
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
	api.NewDNSRepo,
	api.NewGrepApp,
	api.NewHackerTarget,
	//api.NewHunterIO,
	api.NewLeakIX,
	api.NewPassiveTotal,
	api.NewProspeo,
	api.NewSecurityTrails,
	api.NewThreatMiner,
	//api.NewURLScan,
	api.NewVirusTotal,
	api.NewZetalytics,
	archive.NewWayback,
	attribution.NewAttribution,
	aviato.NewAviato,
	bgptools.NewBGPTools,
	breach.NewBreachExposure,
	brute.NewFQDNAlterations,
	cloud.NewCloudRanges,
	dns.NewDNS,
	edgar.NewEDGAR,
	dnssd.NewDNSPlugin,
	enrich.NewBannerURLs,
	enrich.NewContacts,
	enrich.NewEmails,
	enrich.NewTLSCerts,
	enrich.NewURLs,
	gleif.NewGLEIF,
	horizontals.NewHorizontals,
	hp.NewHTTPProbing,
	lookalike.NewLookalikes,
	mtasts.NewMTASTS,
	osm.NewOpenStreetMap,
	securitytxt.NewSecurityTxt,
	sshp.NewSSHProbing,
	bannerp.NewBannerProbing,
	rdap.NewRDAP,
	scrape.NewBing,
	scrape.NewDNSHistory,
	scrape.NewDuckDuckGo,
	scrape.NewIPVerse,
	scrape.NewRapidDNS,
	scrape.NewSiteDossier,
	usaspending.NewUSASpending,
	whois.NewWHOIS,
	NewIPNetblock,
	NewJARMFingerprints,
	NewKnownFQDN,
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
