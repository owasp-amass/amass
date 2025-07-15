// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package brute

import (
	"errors"
	"log/slog"
	"strconv"
	"strings"
	"unicode"

	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
	oamdns "github.com/owasp-amass/open-asset-model/dns"
)

type alts struct {
	name   string
	log    *slog.Logger
	chars  string
	source *et.Source
}

func NewFQDNAlterations() et.Plugin {
	return &alts{
		name:  "FQDN-Alterations",
		chars: "abcdefghijklmnopqrstuvwxyz0123456789-",
		source: &et.Source{
			Name:       "FQDN-Alterations",
			Confidence: 0,
		},
	}
}

func (d *alts) Name() string {
	return d.name
}

func (d *alts) Start(r et.Registry) error {
	d.log = r.Log().WithGroup("plugin").With("name", d.name)

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       d,
		Name:         d.name + "-Handler",
		Priority:     8,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{"fqdn"},
		EventType:    oam.FQDN,
		Callback:     d.check,
	}); err != nil {
		return err
	}

	d.log.Info("Plugin started")
	return nil
}

func (d *alts) Stop() {
	d.log.Info("Plugin stopped")
}

func (d *alts) check(e *et.Event) error {
	fqdn, ok := e.Entity.Asset.(*oamdns.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	cfg := e.Session.Config()
	if cfg != nil && (!cfg.BruteForcing || !cfg.Alterations) {
		return nil
	}

	if e.Meta == nil {
		return nil
	}

	var dom string
	name := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if a, conf := e.Session.Scope().IsAssetInScope(fqdn, 0); conf == 0 || a == nil {
		return nil
	} else if dfqdn, ok := a.(*oamdns.FQDN); !ok || dfqdn == nil {
		return nil
	} else {
		dom = dfqdn.Name
	}

	since, err := support.TTLStartTime(cfg, "FQDN", "FQDN", d.name)
	if err != nil {
		return err
	}

	if support.AssetMonitoredWithinTTL(e.Session, e.Entity, d.source, since) {
		return nil
	}

	guesses := stringset.New()
	defer guesses.Close()

	if cfg.FlipWords && len(cfg.AltWordlist) > 0 {
		guesses.InsertMany(flipWords(name, cfg.AltWordlist)...)
	}
	if cfg.FlipNumbers {
		guesses.InsertMany(flipNumbers(name)...)
	}
	if cfg.AddNumbers {
		guesses.InsertMany(appendNumbers(name)...)
	}
	if cfg.AddWords && len(cfg.AltWordlist) > 0 {
		guesses.InsertMany(addPrefixWords(name, cfg.AltWordlist)...)
		guesses.InsertMany(addSuffixWords(name, cfg.AltWordlist)...)
	}
	if distance := cfg.EditDistance; distance > 0 {
		guesses.InsertMany(fuzzyLabelSearches(name, distance, d.chars)...)
	}
	guesses.Remove(dom)
	guesses.Remove(name)

	var assets []*dbt.Entity
	//subre := dns.SubdomainRegex(dom)
	for _, guess := range guesses.Slice() {
		//if match := subre.FindString(guess); guess != match {
		//	continue
		//}
		if a := d.store(e, guess); a != nil {
			assets = append(assets, a...)
		}
	}

	if len(assets) > 0 {
		d.process(e, assets, d.source)
		support.MarkAssetMonitored(e.Session, e.Entity, d.source)
	}
	return nil
}

func (d *alts) store(e *et.Event, name string) []*dbt.Entity {
	return support.StoreFQDNsWithSource(e.Session, []string{name}, d.source, d.name, d.name+"-Handler")
}

func (d *alts) process(e *et.Event, fqdns []*dbt.Entity, src *et.Source) {
	support.ProcessFQDNsWithSource(e, fqdns, d.source)
}

// flipWords flips prefixes and suffixes found within the provided name.
func flipWords(name string, words []string) []string {
	names := strings.SplitN(name, ".", 2)
	subdomain := names[0]
	domain := names[1]

	parts := strings.Split(subdomain, "-")
	if len(parts) < 2 {
		return []string{}
	}

	var guesses []string
	for _, k := range words {
		guesses = append(guesses, k+"-"+strings.Join(parts[1:], "-")+"."+domain)
	}
	for _, k := range words {
		guesses = append(guesses, strings.Join(parts[:len(parts)-1], "-")+"-"+k+"."+domain)
	}
	return guesses
}

// flipNumbers flips numbers in a subdomain name.
func flipNumbers(name string) []string {
	n := name
	parts := strings.SplitN(n, ".", 2)
	// Find the first character that is a number
	first := strings.IndexFunc(parts[0], unicode.IsNumber)
	if first < 0 {
		return []string{}
	}

	var guesses []string
	// Flip the first number and attempt a second number
	for i := 0; i < 10; i++ {
		sf := n[:first] + strconv.Itoa(i) + n[first+1:]
		guesses = append(guesses, secondNumberFlip(sf, first+1)...)
	}
	// Take the first number out
	guesses = append(guesses, secondNumberFlip(n[:first]+n[first+1:], -1)...)
	return guesses
}

func secondNumberFlip(name string, minIndex int) []string {
	parts := strings.SplitN(name, ".", 2)
	// Find the second character that is a number
	last := strings.LastIndexFunc(parts[0], unicode.IsNumber)
	if last < 0 || last < minIndex {
		return []string{name}
	}

	var guesses []string
	// Flip those numbers and send out the mutations
	for i := 0; i < 10; i++ {
		guesses = append(guesses, name[:last]+strconv.Itoa(i)+name[last+1:])
	}
	// Take the second number out
	guesses = append(guesses, name[:last]+name[last+1:])
	return guesses
}

// appendNumbers appends a number to a subdomain name.
func appendNumbers(name string) []string {
	parts := strings.SplitN(name, ".", 2)

	parts[0] = strings.Trim(parts[0], "-")
	if parts[0] == "" {
		return []string{}
	}

	var guesses []string
	for i := 0; i < 10; i++ {
		guesses = append(guesses, addSuffix(parts, strconv.Itoa(i))...)
	}
	return guesses
}

// addSuffixWords appends a suffix to a subdomain name.
func addSuffixWords(name string, words []string) []string {
	parts := strings.SplitN(name, ".", 2)

	parts[0] = strings.Trim(parts[0], "-")
	if parts[0] == "" {
		return []string{}
	}

	var guesses []string
	for _, word := range words {
		guesses = append(guesses, addSuffix(parts, word)...)
	}
	return guesses
}

// addPrefixWords appends a subdomain name to a prefix.
func addPrefixWords(name string, words []string) []string {
	name = strings.Trim(name, "-")
	if name == "" {
		return []string{}
	}

	var guesses []string
	for _, word := range words {
		guesses = append(guesses, addPrefix(name, word)...)
	}
	return guesses
}

func addSuffix(parts []string, suffix string) []string {
	return []string{
		parts[0] + suffix + "." + parts[1],
		parts[0] + "-" + suffix + "." + parts[1],
	}
}

func addPrefix(name, prefix string) []string {
	return []string{
		prefix + name,
		prefix + "-" + name,
	}
}

// fuzzyLabelSearches returns new names generated by making slight
// mutations to the provided name.
func fuzzyLabelSearches(name string, distance int, chars string) []string {
	parts := strings.SplitN(name, ".", 2)

	var results []string
	if len(parts) < 2 {
		return results
	}

	results = append(results, parts[0])
	for i := 0; i < distance; i++ {
		var conv []string

		conv = append(conv, additions(results, chars)...)
		conv = append(conv, deletions(results)...)
		conv = append(conv, substitutions(results, chars)...)
		results = append(results, conv...)
	}

	var guesses []string
	for _, alt := range results {
		if label := strings.Trim(alt, "-"); label != "" {
			guesses = append(guesses, label+"."+parts[1])
		}
	}
	return guesses
}

func additions(set []string, chars string) []string {
	ldh := []rune(chars)
	ldhLen := len(ldh)

	var guesses []string
	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i <= rlen; i++ {
			for j := 0; j < ldhLen; j++ {
				temp := append(rstr, ldh[0])

				copy(temp[i+1:], temp[i:])
				temp[i] = ldh[j]
				guesses = append(guesses, string(temp))
			}
		}
	}
	return guesses
}

func deletions(set []string) []string {
	var guesses []string

	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i < rlen; i++ {
			if del := string(append(rstr[:i], rstr[i+1:]...)); del != "" {
				guesses = append(guesses, del)
			}
		}
	}
	return guesses
}

func substitutions(set []string, chars string) []string {
	ldh := []rune(chars)
	ldhLen := len(ldh)

	var guesses []string
	for _, str := range set {
		rstr := []rune(str)
		rlen := len(rstr)

		for i := 0; i < rlen; i++ {
			temp := rstr

			for j := 0; j < ldhLen; j++ {
				temp[i] = ldh[j]
				guesses = append(guesses, string(temp))
			}
		}
	}
	return guesses
}
