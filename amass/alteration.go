// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"strconv"
	"strings"
	"time"
	"unicode"
)

// ExecuteAlterations - Runs all the DNS name alteration methods as goroutines
func (a *Amass) ExecuteAlterations(name *Subdomain) {
	go a.FlipNumbersInName(name)
	go a.AppendNumbers(name)
	//go a.PrefixSuffixWords(name)
}

// FlipNumbersInName - Method to flip numbers in a subdomain name
func (a *Amass) FlipNumbersInName(name *Subdomain) {
	n := name.Name
	parts := strings.SplitN(n, ".", 2)
	// Find the first character that is a number
	first := strings.IndexFunc(parts[0], unicode.IsNumber)
	if first < 0 {
		return
	}
	// Flip the first number and attempt a second number
	for i := 0; i < 10; i++ {
		sf := n[:first] + strconv.Itoa(i) + n[first+1:]

		a.secondNumberFlip(sf, name.Domain, first+1)
	}
	// Take the first number out
	a.secondNumberFlip(n[:first]+n[first+1:], name.Domain, -1)
}

func (a *Amass) secondNumberFlip(name, domain string, minIndex int) {
	parts := strings.SplitN(name, ".", 2)
	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		a.sendAlteredName(name, domain)
		return
	}
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		n := name[:last] + strconv.Itoa(i) + name[last+1:]

		a.sendAlteredName(n, domain)
	}
	// Take the second number out
	a.sendAlteredName(name[:last]+name[last+1:], domain)
}

// AppendNumbers - Method for appending a number to a subdomain name
func (a *Amass) AppendNumbers(name *Subdomain) {
	n := name.Name
	parts := strings.SplitN(n, ".", 2)

	for i := 0; i < 10; i++ {
		// Send a LABEL-NUM altered name
		nhn := parts[0] + "-" + strconv.Itoa(i) + "." + parts[1]
		a.sendAlteredName(nhn, name.Domain)
		// Send a LABELNUM altered name
		nn := parts[0] + strconv.Itoa(i) + "." + parts[1]
		a.sendAlteredName(nn, name.Domain)
	}
}

// PrefixSuffixWords - Method for adding words to the prefix and suffix of a subdomain name
func (a *Amass) PrefixSuffixWords(name *Subdomain) {
	// Frequency is the max speed DNS requests will be sent
	t := time.NewTicker(a.Frequency)
	defer t.Stop()

	for _, word := range a.Wordlist {
		<-t.C
		// Send the new names with the word as a prefix and suffix of the leftmost label
		a.prefixWord(name.Name, word, name.Domain)
		a.suffixWord(name.Name, word, name.Domain)
	}
}

func (a *Amass) prefixWord(name, word, domain string) {
	a.sendAlteredName(word+"-"+name, domain)
}

func (a *Amass) suffixWord(name, word, domain string) {
	parts := strings.SplitN(name, ".", 2)
	n := parts[0] + "-" + word + "." + parts[1]

	a.sendAlteredName(n, domain)
}

// Checks that the name is valid and sends along for DNS resolve
func (a *Amass) sendAlteredName(name, domain string) {
	re := SubdomainRegex(domain)

	if re.MatchString(name) {
		a.Names <- &Subdomain{
			Name:   name,
			Domain: domain,
			Tag:    ALT,
		}
	}
}
