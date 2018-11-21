// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package core

import (
	"errors"
	"io"
	"io/ioutil"
	"log"
	"time"

	"github.com/OWASP/Amass/amass/utils"
	evbus "github.com/asaskevich/EventBus"
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
	MaxConnections utils.Semaphore
)

// EnumerationTiming represents a speed band for the enumeration to execute within.
type EnumerationTiming int

// Enumeration is the object type used to execute a DNS enumeration with Amass.
type Enumeration struct {
	Config *AmassConfig

	Bus evbus.Bus

	// Link graph that collects all the information gathered by the enumeration
	Graph *Graph

	// The channel that will receive the results
	Output chan *AmassOutput

	// Broadcast channel that indicates no further writes to the output channel
	Done chan struct{}

	// Logger for error messages
	Log *log.Logger

	// The writer used to save the data operations performed
	DataOptsWriter io.Writer

	// MaxFlow is a Semaphore that restricts the number of names moving through the architecture
	MaxFlow utils.Semaphore

	trustedNameFilter *utils.StringFilter
	otherNameFilter   *utils.StringFilter

	// Pause/Resume channels for halting the enumeration
	pause  chan struct{}
	resume chan struct{}
}

func init() {
	NumOfFileDescriptors = (GetFileLimit() / 10) * 9
	MaxConnections = utils.NewSimpleSemaphore(NumOfFileDescriptors)
}

// NewEnumeration returns an initialized Enumeration that has not been started yet.
func NewEnumeration() *Enumeration {
	enum := &Enumeration{
		Config: &AmassConfig{
			Ports:           []int{443},
			Recursive:       true,
			MinForRecursive: 1,
			Alterations:     true,
			Timing:          Normal,
		},
		Bus:               evbus.New(),
		Graph:             NewGraph(),
		Output:            make(chan *AmassOutput, 100),
		Done:              make(chan struct{}),
		Log:               log.New(ioutil.Discard, "", 0),
		trustedNameFilter: utils.NewStringFilter(),
		otherNameFilter:   utils.NewStringFilter(),
		pause:             make(chan struct{}),
		resume:            make(chan struct{}),
	}
	return enum
}

// DataSourceNameFilter provides a single output filter for all name sources.
func (e *Enumeration) DupDataSourceName(req *AmassRequest) bool {
	if req == nil {
		return true
	}

	tt := TrustedTag(req.Tag)
	if !tt && e.otherNameFilter.Duplicate(req.Name) {
		return true
	} else if tt && e.trustedNameFilter.Duplicate(req.Name) {
		return true
	}
	return false
}

// CheckConfig runs some sanity checks on the enumeration configuration.
func (e *Enumeration) CheckConfig() error {
	if e.Output == nil {
		return errors.New("The configuration did not have an output channel")
	}
	if e.Config.Passive && e.Config.BruteForcing {
		return errors.New("Brute forcing cannot be performed without DNS resolution")
	}
	if e.Config.Passive && e.Config.Active {
		return errors.New("Active enumeration cannot be performed without DNS resolution")
	}
	if e.Config.Passive && e.DataOptsWriter != nil {
		return errors.New("Data operations cannot be saved without DNS resolution")
	}
	if len(e.Config.Ports) == 0 {
		e.Config.Ports = []int{443}
	}

	e.MaxFlow = utils.NewTimedSemaphore(
		e.Config.Timing.ToMaxFlow(),
		e.Config.Timing.ToReleaseDelay())
	return nil
}

// Pause temporarily halts the enumeration.
func (e *Enumeration) Pause() {
	e.pause <- struct{}{}
}

// PauseChan returns the channel that is signaled when Pause is called.
func (e *Enumeration) PauseChan() <-chan struct{} {
	return e.pause
}

// Resume causes a previously paused enumeration to resume execution.
func (e *Enumeration) Resume() {
	e.resume <- struct{}{}
}

// ResumeChan returns the channel that is signaled when Resume is called.
func (e *Enumeration) ResumeChan() <-chan struct{} {
	return e.resume
}

// SendOutput is a wrapper for sending enumeration output to the appropriate channel.
func (e *Enumeration) SendOutput(out *AmassOutput) {
	e.Output <- out
}

// TrustedTag returns true when the tag parameter is of a type that should be trusted even
// facing DNS wildcards.
func TrustedTag(tag string) bool {
	if tag == DNS || tag == CERT || tag == ARCHIVE || tag == AXFR {
		return true
	}
	return false
}

// ToMaxFlow returns the maximum number of names Amass should handle at once.
func (t EnumerationTiming) ToMaxFlow() int {
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

// ToReleaseDelay returns the minimum delay between each MaxFlow semaphore release.
func (t EnumerationTiming) ToReleaseDelay() time.Duration {
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

// ToReleasesPerSecond returns the number of releases performed on MaxFlow each second.
func (t EnumerationTiming) ToReleasesPerSecond() int {
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
