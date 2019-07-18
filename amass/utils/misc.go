// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package utils

import (
	"bufio"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/irfansharif/cfilter"
)

const (
	// IPv4RE is a regular expression that will match an IPv4 address.
	IPv4RE = "((25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)[.]){3}(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)"

	// SUBRE is a regular expression that will match on all subdomains once the domain is appended.
	SUBRE = "(([a-zA-Z0-9]{1}|[_a-zA-Z0-9]{1}[_a-zA-Z0-9-]{0,61}[a-zA-Z0-9]{1})[.]{1})+"

	tldList = "https://raw.githubusercontent.com/OWASP/Amass/develop/wordlists/tldlist.txt"

	maskLetters = "abcdefghijklmnopqrstuvwxyz"
	maskDigits  = "0123456789"
	maskSpecial = "-"
)

var (
	// KnownValidTLDs is a list of valid top-level domains that is maintained by the IANA.
	KnownValidTLDs []string
)

func getTLDList() []string {
	page, err := RequestWebPage(tldList, nil, nil, "", "")
	if err != nil {
		return nil
	}
	return getWordList(strings.NewReader(page))
}

func getWordList(reader io.Reader) []string {
	var words []string

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		// Get the next word in the list
		w := strings.TrimSpace(scanner.Text())
		if err := scanner.Err(); err == nil && w != "" && !strings.Contains(w, "-") {
			words = append(words, w)
		}
	}
	return words
}

type filterRequest struct {
	String string
	Result chan bool
}

// StringFilter implements an object that performs filtering of strings
// to ensure that only unique items get through the filter.
type StringFilter struct {
	filter   *cfilter.CFilter
	requests chan filterRequest
	quit     chan struct{}
}

// NewStringFilter returns an initialized StringFilter.
func NewStringFilter() *StringFilter {
	sf := &StringFilter{
		filter:   cfilter.New(),
		requests: make(chan filterRequest),
		quit:     make(chan struct{}),
	}
	go sf.processRequests()
	return sf
}

// Duplicate checks if the name provided has been seen before by this filter.
func (sf *StringFilter) Duplicate(s string) bool {
	result := make(chan bool)

	sf.requests <- filterRequest{String: s, Result: result}
	return <-result
}

func (sf *StringFilter) processRequests() {
	for {
		select {
		case <-sf.quit:
			return
		case r := <-sf.requests:
			if sf.filter.Lookup([]byte(r.String)) {
				r.Result <- true
			} else {
				sf.filter.Insert([]byte(r.String))
				r.Result <- false
			}
		}
	}
}

// SubdomainRegex returns a Regexp object initialized to match
// subdomain names that end with the domain provided by the parameter.
func SubdomainRegex(domain string) *regexp.Regexp {
	// Change all the periods into literal periods for the regex
	d := strings.Replace(domain, ".", "[.]", -1)

	return regexp.MustCompile(SUBRE + d)
}

// AnySubdomainRegex returns a Regexp object initialized to match any DNS subdomain name.
func AnySubdomainRegex() *regexp.Regexp {
	return regexp.MustCompile(SUBRE + "[a-zA-Z]{0,61}")
}

// NewUniqueElements removes elements that have duplicates in the original or new elements.
func NewUniqueElements(orig []string, add ...string) []string {
	var n []string

	for _, av := range add {
		found := false
		s := strings.ToLower(av)

		// Check the original slice for duplicates
		for _, ov := range orig {
			if s == strings.ToLower(ov) {
				found = true
				break
			}
		}
		// Check that we didn't already add it in
		if !found {
			for _, nv := range n {
				if s == nv {
					found = true
					break
				}
			}
		}
		// If no duplicates were found, add the entry in
		if !found {
			n = append(n, s)
		}
	}
	return n
}

// UniqueAppend behaves like the Go append, but does not add duplicate elements.
func UniqueAppend(orig []string, add ...string) []string {
	return append(orig, NewUniqueElements(orig, add...)...)
}

// CopyString return a new string variable with the same value as the parameter.
func CopyString(src string) string {
	str := make([]byte, len(src))

	copy(str, src)
	return string(str)
}

// RemoveAsteriskLabel returns the provided DNS name with all asterisk labels removed.
func RemoveAsteriskLabel(s string) string {
	var index int

	labels := strings.Split(s, ".")
	for i := len(labels) - 1; i >= 0; i-- {
		if strings.TrimSpace(labels[i]) == "*" {
			break
		}
		index = i
	}
	if index == len(labels)-1 {
		return ""
	}
	return strings.Join(labels[index:], ".")
}

func ExpandMask(word string) ([]string, error) {
	var expanded []string
	var chars string

	if strings.Count(word, "?") > 3 {
		return expanded, fmt.Errorf("Exceeded maximum mask size (3): %s", word)
	}

	parts := strings.SplitN(word, "?", 2)
	if len(parts) > 1 {
		if len(parts[1]) > 0 {
			switch parts[1][0] {
			case 'a':
				chars = maskLetters + maskDigits + maskSpecial
			case 'd':
				chars = maskDigits
			case 'u':
				fallthrough
			case 'l':
				chars = maskLetters
			case 's':
				chars = maskSpecial
			default:
				return expanded, fmt.Errorf("Improper mask used: %s", word)
			}
			for _, ch := range chars {
				newWord := parts[0] + string(ch) + parts[1][1:]
				nextRound, err := ExpandMask(newWord)
				if err != nil {
					return expanded, err
				}
				expanded = append(expanded, nextRound...)
			}
		}
	} else {
		expanded = append(expanded, word)
	}
	return expanded, nil
}

func ExpandMaskWordlist(wordlist []string) ([]string, error) {
	var newWordlist []string
	var newWords []string
	var err error

	for _, word := range wordlist {
		newWords, err = ExpandMask(word)
		if err != nil {
			break
		}

		newWordlist = append(newWordlist, newWords...)
	}

	return newWordlist, err
}

// ReverseString returns the characters of the argument string in reverse order.
func ReverseString(s string) string {
	chrs := []rune(s)

	end := len(chrs) / 2
	for i, j := 0, len(chrs)-1; i < end; i, j = i+1, j-1 {
		chrs[i], chrs[j] = chrs[j], chrs[i]
	}
	return string(chrs)
}
