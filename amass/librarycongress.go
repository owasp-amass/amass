// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type libraryCongress struct {
	memento Archiver
}

func (l libraryCongress) String() string {
	return "Library of Congress Archive"
}

func (l *libraryCongress) CheckHistory(subdomain string) {
	l.memento.CheckHistory(subdomain)
	return
}

func (l libraryCongress) TotalUniqueSubdomains() int {
	return l.memento.TotalUniqueSubdomains()
}

func LibraryCongressArchive(subdomains chan string) Archiver {
	l := new(libraryCongress)

	l.memento = MementoWebArchive("http://webarchive.loc.gov/all", subdomains)
	if l.memento == nil {
		return nil
	}
	return l
}
