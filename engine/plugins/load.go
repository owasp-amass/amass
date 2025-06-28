// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"github.com/owasp-amass/amass/v4/engine/plugins/api"
	"github.com/owasp-amass/amass/v4/engine/plugins/api/aviato"
	"github.com/owasp-amass/amass/v4/engine/plugins/api/gleif"
	"github.com/owasp-amass/amass/v4/engine/plugins/api/rdap"
	"github.com/owasp-amass/amass/v4/engine/plugins/archive"
	"github.com/owasp-amass/amass/v4/engine/plugins/brute"
	"github.com/owasp-amass/amass/v4/engine/plugins/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/enrich"
	"github.com/owasp-amass/amass/v4/engine/plugins/horizontals"
	"github.com/owasp-amass/amass/v4/engine/plugins/scrape"
	hp "github.com/owasp-amass/amass/v4/engine/plugins/service_discovery/http_probes"
	dns_sd "github.com/owasp-amass/amass/v4/engine/plugins/service_discovery/dns"
	"github.com/owasp-amass/amass/v4/engine/plugins/whois"
	"github.com/owasp-amass/amass/v4/engine/plugins/whois/bgptools"
	et "github.com/owasp-amass/amass/v4/engine/types"
)

var pluginNewFuncs = []func() et.Plugin{
	api.NewBinaryEdge,
	api.NewChaos,
	api.NewCrtsh,
	api.NewDNSRepo,
	api.NewGrepApp,
	api.NewHackerTarget,
	//api.NewHunterIO,
	api.NewLeakIX,
	api.NewPassiveTotal,
	api.NewProspeo,
	api.NewSecurityTrails,
	//api.NewURLScan,
	api.NewVirusTotal,
	api.NewZetalytics,
	archive.NewWayback,
	aviato.NewAviato,
	bgptools.NewBGPTools,
	brute.NewFQDNAlterations,
	dns.NewDNS,
	dns_sd.NewDNSPlugin,
	enrich.NewBannerURLs,
	enrich.NewContacts,
	enrich.NewEmails,
	enrich.NewTLSCerts,
	enrich.NewURLs,
	gleif.NewGLEIF,
	horizontals.NewHorizontals,
	hp.NewHTTPProbing,
	rdap.NewRDAP,
	scrape.NewBing,
	scrape.NewDNSHistory,
	scrape.NewDuckDuckGo,
	scrape.NewIPVerse,
	scrape.NewRapidDNS,
	scrape.NewSiteDossier,
	whois.NewWHOIS,
	NewIPNetblock,
	NewJARMFingerprints,
	NewKnownFQDN,
	NewVerifiedEmail,
}

func LoadAndStartPlugins(r et.Registry) error {
	var started []et.Plugin

	for _, f := range pluginNewFuncs {
		if p := f(); p != nil {
			if err := p.Start(r); err != nil {
				stopPlugins(started)
				return err
			}
		}
	}
	return nil
}

func stopPlugins(started []et.Plugin) {
	for _, p := range started {
		p.Stop()
	}
}