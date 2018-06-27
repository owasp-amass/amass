package sources

import (
	"log"
)

const (
	OpenUKArchiveSourceString string = "Open UK Arc"
	openukArchiveURL          string = "http://www.webarchive.org.uk/wayback/archive"
)

func OpenUKArchiveQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	return runArchiveCrawler(openukArchiveURL, domain, sub, l)
}
