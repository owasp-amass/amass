// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"time"

	"github.com/OWASP/Amass/amass/utils"
)

// Various types used throughout Amass
const (
	ACTIVECERT = "amass:activecert"
	CHECKED    = "amass:checked"
	DNSQUERY   = "amass:dnsquery"
	DNSSWEEP   = "amass:dnssweep"
	NEWADDR    = "amass:newaddress"
	NEWNAME    = "amass:newname"
	NEWSUB     = "amass:newsubdomain"
	OUTPUT     = "amass:output"
	RELEASEREQ = "amass:releaserequest"
	RESOLVED   = "amass:resolved"

	ALT     = "alt"
	ARCHIVE = "archive"
	API     = "api"
	AXFR    = "axfr"
	BRUTE   = "brute"
	CERT    = "cert"
	DNS     = "dns"
	SCRAPE  = "scrape"
)

// EnumerationTiming represents a speed band for the enumeration to execute within.
type EnumerationTiming int

// The various timing/speed templates for an Amass enumeration.
const (
	Paranoid EnumerationTiming = iota
	Sneaky
	Polite
	Normal
	Aggressive
	Insane
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

// TimingToMaxFlow returns the maximum number of names Amass should handle at once.
func TimingToMaxFlow(t EnumerationTiming) int {
	var result int

	switch t {
	case Paranoid:
		result = 10
	case Sneaky:
		result = 30
	case Polite:
		result = 100
	case Normal:
		result = 333
	case Aggressive:
		result = 1000
	case Insane:
		result = 10000
	}
	return result
}

// TimingToReleaseDelay returns the minimum delay between each MaxFlow semaphore release.
func TimingToReleaseDelay(t EnumerationTiming) time.Duration {
	var result time.Duration

	switch t {
	case Paranoid:
		result = 100 * time.Millisecond
	case Sneaky:
		result = 33 * time.Millisecond
	case Polite:
		result = 10 * time.Millisecond
	case Normal:
		result = 3 * time.Millisecond
	case Aggressive:
		result = time.Millisecond
	case Insane:
		result = 100 * time.Microsecond
	}
	return result
}

// TimingToReleasesPerSecond returns the number of releases performed on MaxFlow each second.
func TimingToReleasesPerSecond(t EnumerationTiming) int {
	var result int

	switch t {
	case Paranoid:
		result = 10
	case Sneaky:
		result = 30
	case Polite:
		result = 100
	case Normal:
		result = 333
	case Aggressive:
		result = 1000
	case Insane:
		result = 10000
	}
	return result
}
