// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"math/rand"
	"os"
	"time"

	"github.com/OWASP/Amass/amass"
	"github.com/OWASP/Amass/amass/core"
	"github.com/sensepost/maltegolocal/maltegolocal"
)

func main() {
	var domain string

	lt := maltegolocal.ParseLocalArguments(os.Args)
	domain = lt.Value
	trx := maltegolocal.MaltegoTransform{}
	
	enum := amass.NewEnumeration()

	go func() {
		for n := range enum.Output {
			if n != nil && n.Domain == domain {
				entity := trx.AddEntity("maltego.DNSName", n.Name)

				switch n.Type {
				case core.TypeNorm:
					entity.AddProperty("Fqdn", "DNS Name", "", n.Name)
				case core.TypeNS:
					entity.SetType("maltego.NSRecord")
					entity.AddProperty("fqdn", "NS Record", "", n.Name)
				case core.TypeMX:
					entity.SetType("maltego.MXRecord")
					entity.AddProperty("fqdn", "MX Record", "", n.Name)
				case core.TypeWeb:
					entity.SetType("maltego.Website")
					entity.AddProperty("fqdn", "Website", "", n.Name)
				}

			}
		}
	}()

	trx.AddUIMessage("The amass transform can take a few minutes to complete.", "Inform")
	// Seed the pseudo-random number generator
	rand.Seed(time.Now().UTC().UnixNano())
	enum.AddDomain(domain)
	// Begin the enumeration process
	enum.Start()
	time.Sleep(2 * time.Second)
	fmt.Println(trx.ReturnOutput())
}
