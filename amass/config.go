// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"time"
)

// AmassConfig - Passes along optional configurations
type AmassConfig struct {
	// The root domain names that the enumeration will target
	Domains []string

	// The list of words to use when generating names
	Wordlist []string

	// Will the enumeration including brute forcing techniques
	BruteForcing bool

	// Will recursive brute forcing be performed?
	Recursive bool

	// Sets the maximum number of DNS queries per minute
	Frequency time.Duration

	// The channel that will receive the results
	Output chan *AmassRequest
}

// DefaultConfig returns a config with values that have been tested and produce desirable results
func DefaultConfig() AmassConfig {
	return AmassConfig{
		Wordlist:  []string{},
		Frequency: 5 * time.Millisecond,
	}
}

// Ensures that all configuration elements have valid values
func customConfig(ac AmassConfig) AmassConfig {
	config := DefaultConfig()

	// Check that the config values have been set appropriately
	if ac.Frequency > config.Frequency {
		config.Frequency = ac.Frequency
	}
	config.Wordlist = ac.Wordlist
	return config
}
