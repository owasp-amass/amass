// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bufio"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/caffix/amass/amass"
	"github.com/sensepost/maltegolocal/maltegolocal"
)

const (
	defaultWordlistURL = "https://raw.githubusercontent.com/caffix/amass/master/wordlists/namelist.txt"
)

func main() {
	var domain string

	lt := maltegolocal.ParseLocalArguments(os.Args)
	domain = lt.Value
	trx := maltegolocal.MaltegoTransform{}

	config := amass.AmassConfig{
		Wordlist:  getWordlist(""),
		Frequency: amass.DefaultConfig().Frequency,
	}
	// Seed the pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())
	// Fire off the driver function for enumeration
	enum := amass.NewEnumerator([]string{domain}, false, config)

	go func() {
		for {
			n := <-enum.Names
			if n.Domain == domain {
				trx.AddEntity("maltego.DNSName", n.Name)
			}
		}
	}()

	trx.AddUIMessage("The amass transform can take a few minutes to complete.", "Inform")
	// Begin the enumeration process
	enum.Start()
	fmt.Println(trx.ReturnOutput())
}

func getWordlist(path string) []string {
	var list []string
	var wordlist io.Reader

	if path != "" {
		// Open the wordlist
		file, err := os.Open(path)
		if err != nil {
			fmt.Printf("Error opening the wordlist file: %v\n", err)
			return list
		}
		defer file.Close()
		wordlist = file
	} else {
		resp, err := http.Get(defaultWordlistURL)
		if err != nil {
			return list
		}
		defer resp.Body.Close()
		wordlist = resp.Body
	}

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
