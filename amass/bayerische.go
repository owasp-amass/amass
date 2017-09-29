// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type bayerische struct {
	memento Archiver
}

func (b bayerische) String() string {
	return "Bayerische Staatsbibliothek Archive"
}

func (b *bayerische) CheckHistory(subdomain string) {
	b.memento.CheckHistory(subdomain)
	return
}

func (b bayerische) TotalUniqueSubdomains() int {
	return b.memento.TotalUniqueSubdomains()
}

func BayerischeArchive(subdomains chan string) Archiver {
	b := new(bayerische)

	b.memento = MementoWebArchive("http://langzeitarchivierung.bib-bvb.de/wayback", subdomains)
	if b.memento == nil {
		return nil
	}
	return b
}
