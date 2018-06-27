// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"log"
)

const (
	ArquivoSourceString string = "Arquivo Arc"
	arquivoURL          string = "http://arquivo.pt/wayback"
)

func ArquivoQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(arquivoURL, domain, sub, l)
}
