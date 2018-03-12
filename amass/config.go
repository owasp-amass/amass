// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"bufio"
	"errors"
	"io"
	"net/http"
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

func CheckConfig(config *AmassConfig) error {
	if len(config.Domains) == 0 {
		return errors.New("The configuration contains no domain names")
	}

	if len(config.Wordlist) == 0 {
		return errors.New("The configuration contains no wordlist")
	}

	if config.Frequency < DefaultConfig().Frequency {
		return errors.New("The configuration contains a invalid frequency")
	}

	if config.Output == nil {
		return errors.New("The configuration did not have an output channel")
	}
	return nil
}

// DefaultConfig returns a config with values that have been tested
func DefaultConfig() *AmassConfig {
	return &AmassConfig{
		Recursive: true,
		Frequency: 5 * time.Millisecond,
	}
}

// Ensures that all configuration elements have valid values
func CustomConfig(ac *AmassConfig) *AmassConfig {
	config := DefaultConfig()

	config.Domains = ac.Domains

	if len(ac.Wordlist) == 0 {
		config.Wordlist = GetDefaultWordlist()
	} else {
		config.Wordlist = ac.Wordlist
	}

	config.BruteForcing = ac.BruteForcing
	config.Recursive = ac.Recursive

	// Check that the config values have been set appropriately
	if ac.Frequency > config.Frequency {
		config.Frequency = ac.Frequency
	}

	config.Output = ac.Output
	return config
}

func GetDefaultWordlist() []string {
	var list []string
	var wordlist io.Reader

	resp, err := http.Get(defaultWordlistURL)
	if err != nil {
		return list
	}
	defer resp.Body.Close()
	wordlist = resp.Body

	scanner := bufio.NewScanner(wordlist)
	// Once we have used all the words, we are finished
	for scanner.Scan() {
		// Get the next word in the list
		word := scanner.Text()
		if word != "" {
			// Add the word to the list
			list = append(list, word)
		}
	}
	return list
}
