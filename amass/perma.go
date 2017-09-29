// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type perma struct {
	memento Archiver
}

func (p perma) String() string {
	return "Perma Archive"
}

func (p *perma) CheckHistory(subdomain string) {
	p.memento.CheckHistory(subdomain)
	return
}

func (p perma) TotalUniqueSubdomains() int {
	return p.memento.TotalUniqueSubdomains()
}

func PermaArchive(subdomains chan string) Archiver {
	p := new(perma)

	p.memento = MementoWebArchive("http://perma-archives.org/warc", subdomains)
	if p.memento == nil {
		return nil
	}
	return p
}
