// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import "github.com/OWASP/Amass/amass/utils"

// Various types used throughout Amass
const (
	NEWNAME  = "amass:newname"
	NEWSUB   = "amass:newsubdomain"
	DNSQUERY = "amass:dnsquery"
	DNSSWEEP = "amass.dnssweep"
	RESOLVED = "amass:resolved"
	CHECKED  = "amass:checked"
	OUTPUT   = "amass:output"

	ALT     = "alt"
	ARCHIVE = "archive"
	API     = "api"
	AXFR    = "axfr"
	BRUTE   = "brute"
	CERT    = "cert"
	DNS     = "dns"
	SCRAPE  = "scrape"
)

var (
	// NumOfFileDescriptors is the maximum number of file descriptors or handles to be in use at once.
	NumOfFileDescriptors int

	// MaxConnections creates a limit for how many network connections will be in use at once.
	MaxConnections *utils.Semaphore
)

func init() {
	NumOfFileDescriptors = (GetFileLimit() / 10) * 9
	MaxConnections = utils.NewSemaphore(NumOfFileDescriptors)
}

// TrustedTag returns true when the tag parameter is of a type that should be trusted even
// facing DNS wildcards.
func TrustedTag(tag string) bool {
	if tag == ARCHIVE || tag == AXFR || tag == CERT || tag == DNS {
		return true
	}
	return false
}
