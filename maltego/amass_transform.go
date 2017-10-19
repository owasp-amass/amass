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
	names := make(chan *amass.Subdomain, 100)

	lt := maltegolocal.ParseLocalArguments(os.Args)
	domains = append(domains, lt.Value)

	trx := maltegolocal.MaltegoTransform{}

	go func() {
		for {
			n := <-names

			if n.Domain == domains[0] {
				trx.AddEntity("maltego.DNSName", n.Name)
			}
		}
	}()

	trx.AddUIMessage("The amass transform can take a few minutes to complete.", "Inform")

	a := amass.NewAmass()
	if a != nil {
		a.LookupSubdomainNames(domains, names)
	}

	fmt.Println(trx.ReturnOutput())
}
