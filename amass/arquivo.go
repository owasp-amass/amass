// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

type arquivo struct {
	memento Archiver
}

func (a arquivo) String() string {
	return "Arquivo Archive"
}

func (a *arquivo) CheckHistory(subdomain string) {
	a.memento.CheckHistory(subdomain)
	return
}

func (a arquivo) TotalUniqueSubdomains() int {
	return a.memento.TotalUniqueSubdomains()
}

func ArquivoArchive(subdomains chan string) Archiver {
	a := new(arquivo)

	a.memento = MementoWebArchive("http://arquivo.pt/wayback", subdomains)
	if a.memento == nil {
		return nil
	}
	return a
}
