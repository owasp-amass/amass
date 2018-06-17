// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"log"

	"github.com/caffix/amass/amass/internal/utils"
)

const (
	SiteDossierSourceString string = "SiteDossier"
)

func SiteDossierQuery(domain, sub string, l *log.Logger) []string {
	var unique []string

	if domain != sub {
		return unique
	}

	re := utils.SubdomainRegex(domain)
	url := siteDossierURL(domain)
	page, err := utils.GetWebPage(url, nil)
	if err != nil {
		l.Printf("SiteDossier error: %s: %v", url, err)
		return unique
	}

	for _, sd := range re.FindAllString(page, -1) {
		if u := utils.NewUniqueElements(unique, sd); len(u) > 0 {
			unique = append(unique, u...)
		}
	}
	return unique
}

func siteDossierURL(domain string) string {
	format := "http://www.sitedossier.com/parentdomain/%s"

	return fmt.Sprintf(format, domain)
}
