// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type archiveIs struct {
	memento Archiver
}

func (a archiveIs) String() string {
	return "ArchiveIs Archive"
}

func (a *archiveIs) CheckHistory(subdomain string) {
	a.memento.CheckHistory(subdomain)
	return
}

func (a archiveIs) TotalUniqueSubdomains() int {
	return a.memento.TotalUniqueSubdomains()
}

func ArchiveIsArchive(subdomains chan string) Archiver {
	a := new(archiveIs)

	a.memento = MementoWebArchive("http://archive.is", subdomains)
	if a.memento == nil {
		return nil
	}
	return a
}
