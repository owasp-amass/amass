// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type archiveIt struct {
	memento Archiver
}

func (a archiveIt) String() string {
	return "Archive-It Archive"
}

func (a *archiveIt) CheckHistory(subdomain string) {
	a.memento.CheckHistory(subdomain)
	return
}

func (a archiveIt) TotalUniqueSubdomains() int {
	return a.memento.TotalUniqueSubdomains()
}

func ArchiveItArchive(subdomains chan string) Archiver {
	a := new(archiveIt)

	a.memento = MementoWebArchive("https://wayback.archive-it.org/all", subdomains)
	if a.memento == nil {
		return nil
	}
	return a
}
