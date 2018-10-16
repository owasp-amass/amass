// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

const (
	// Topics used in the EventBus
	NEWNAME  = "amass:newname"
	NEWSUB   = "amass:newsubdomain"
	DNSQUERY = "amass:dnsquery"
	DNSSWEEP = "amass.dnssweep"
	RESOLVED = "amass:resolved"
	OUTPUT   = "amass:output"

	// Tags used to mark the data source with the Subdomain struct
	ALT     = "alt"
	ARCHIVE = "archive"
	API     = "api"
	AXFR    = "axfr"
	BRUTE   = "brute"
	CERT    = "cert"
	DNS     = "dns"
	SCRAPE  = "scrape"

	// Node types used in the Maltego local transform
	TypeNorm int = iota
	TypeNS
	TypeMX
	TypeWeb
)

func TrustedTag(tag string) bool {
	if tag == ARCHIVE || tag == AXFR || tag == CERT || tag == DNS {
		return true
	}
	return false
}
