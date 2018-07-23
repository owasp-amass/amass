// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/NoobieDog/maltegolocal"
	"github.com/OWASP/Amass/amass"
)

func main() {
	var domain string

	lt := maltegolocal.ParseLocalArguments(os.Args)
	domain = lt.Value
	trx := maltegolocal.MaltegoTransform{}
	results := make(chan *amass.AmassOutput, 50)

	go func() {
		for n := range results {
			if n != nil && n.Domain == domain {
				entity := trx.AddEntity("maltego.DNSName", n.Name)

				switch n.Type {
				case amass.TypeNorm:
					entity.AddProperty("Fqdn", "DNS Name", "", n.Name)
				case amass.TypeNS:
					entity.SetType("maltego.NSRecord")
					entity.AddProperty("fqdn", "NS Record", "", n.Name)
				case amass.TypeMX:
					entity.SetType("maltego.MXRecord")
					entity.AddProperty("fqdn", "MX Record", "", n.Name)
				case amass.TypeWeb:
					entity.SetType("maltego.Website")
					entity.AddProperty("fqdn", "Website", "", n.Name)
				}

			}
		}
	}()

	trx.AddUIMessage("The amass transform can take a few minutes to complete.", "Inform")

	// Seed the pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())
	// Setup the amass configuration
	config := amass.CustomConfig(&amass.AmassConfig{
		BruteForcing: false,
		Recursive:    false,
		Alterations:  true,
		Output:       results,
	})
	config.AddDomain(domain)
	// Begin the enumeration process
	amass.StartEnumeration(config)
	time.Sleep(2 * time.Second)
	fmt.Println(trx.ReturnOutput())
}
