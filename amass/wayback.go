// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type wayback struct {
	memento Archiver
}

func (w wayback) String() string {
	return "Wayback Machine Archive"
}

func (w *wayback) CheckHistory(subdomain string) {
	w.memento.CheckHistory(subdomain)
	return
}

func (w wayback) TotalUniqueSubdomains() int {
	return w.memento.TotalUniqueSubdomains()
}

func WaybackMachineArchive(subdomains chan string) Archiver {
	w := new(wayback)

	w.memento = MementoWebArchive("http://web.archive.org/web", subdomains)
	if w.memento == nil {
		return nil
	}
	return w
}
