// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

const (
	// Topics used in the EventBus
	DNSQUERY = "amass:dnsquery"
	DNSSWEEP = "amass.dnssweep"
	RESOLVED = "amass:resolved"
	OUTPUT   = "amass:output"

	// Tags used to mark the data source with the Subdomain struct
	ALT     = "alt"
	ARCHIVE = "archive"
	API     = "api"
	BRUTE   = "brute"
	CERT    = "cert"
	SCRAPE  = "scrape"

	// Node types used in the Maltego local transform
	TypeNorm int = iota
	TypeNS
	TypeMX
	TypeWeb
)
