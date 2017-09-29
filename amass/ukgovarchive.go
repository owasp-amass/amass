// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type ukGov struct {
	memento Archiver
}

func (u ukGov) String() string {
	return "UK Government Web Archive"
}

func (u *ukGov) CheckHistory(subdomain string) {
	u.memento.CheckHistory(subdomain)
	return
}

func (u ukGov) TotalUniqueSubdomains() int {
	return u.memento.TotalUniqueSubdomains()
}

func UKGovArchive(subdomains chan string) Archiver {
	u := new(ukGov)

	u.memento = MementoWebArchive("http://webarchive.nationalarchives.gov.uk", subdomains)
	if u.memento == nil {
		return nil
	}
	return u
}
