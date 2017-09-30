// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

func ArchiveItArchive(subdomains chan string) Archiver {
	return MementoWebArchive("https://wayback.archive-it.org/all", subdomains)
}

func ArchiveIsArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://archive.is", subdomains)
}

func ArquivoArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://arquivo.pt/wayback", subdomains)
}

func BayerischeArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://langzeitarchivierung.bib-bvb.de/wayback", subdomains)
}

func LibraryCongressArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://webarchive.loc.gov/all", subdomains)
}

func PermaArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://perma-archives.org/warc", subdomains)
}

func UKWebArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://www.webarchive.org.uk/wayback/archive", subdomains)
}

func UKGovArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://webarchive.nationalarchives.gov.uk", subdomains)
}

func WaybackMachineArchive(subdomains chan string) Archiver {
	return MementoWebArchive("http://web.archive.org/web", subdomains)
}
