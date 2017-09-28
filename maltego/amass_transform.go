// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"fmt"
	"os"

	"github.com/caffix/amass/amass"
	"github.com/sensepost/maltegolocal/maltegolocal"
)

func main() {
	var domains []string
	var names chan *amass.ValidSubdomain = make(chan *amass.ValidSubdomain, 10)

	lt := maltegolocal.ParseLocalArguments(os.Args)
	domains = append(domains, lt.Value)

	trx := maltegolocal.MaltegoTransform{}

	go func() {
		for {
			n := <-names

			if n.Subdomain != domains[0] {
				trx.AddEntity("maltego.DNSName", n.Subdomain)
			}
		}
	}()

	trx.AddUIMessage("The amass transform can take a few minutes to complete.", "Inform")
	amass.LookupSubdomainNames(domains, names, nil)

	fmt.Println(trx.ReturnOutput())
}
