// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type ukWeb struct {
	memento Archiver
}

func (u ukWeb) String() string {
	return "UK Web Archive"
}

func (u *ukWeb) CheckHistory(subdomain string) {
	u.memento.CheckHistory(subdomain)
	return
}

func (u ukWeb) TotalUniqueSubdomains() int {
	return u.memento.TotalUniqueSubdomains()
}

func UKWebArchive(subdomains chan string) Archiver {
	u := new(ukWeb)

	u.memento = MementoWebArchive("http://www.webarchive.org.uk/wayback/archive", subdomains)
	if u.memento == nil {
		return nil
	}
	return u
}
