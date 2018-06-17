package sources

import (
	"fmt"
	"log"
	"regexp"
	"strconv"
	"time"

	"github.com/PuerkitoBio/gocrawl"
	"github.com/caffix/amass/amass/internal/utils"
)

const (
	ArquivoSourceString string = "Arquivo Arc"
	arquivoURL          string = "http://arquivo.pt/wayback"
)

func ArquivoQuery(domain, sub string, l *log.Logger) []string {
	if sub == "" {
		return []string{}
	}

	year := strconv.Itoa(time.Now().Year())
	ext := &ext{
		DefaultExtender: &gocrawl.DefaultExtender{},
		source:          ArquivoSourceString,
		domainRE:        utils.SubdomainRegex(domain),
		mementoRE:       regexp.MustCompile(arquivoURL + "/[0-9]+/"),
		filter:          make(map[string]bool), // Filter for not double-checking URLs
		base:            arquivoURL,
		year:            year,
		sub:             sub,
		logger:          l,
	}

	// Set custom options
	opts := gocrawl.NewOptions(ext)
	opts.CrawlDelay = 50 * time.Millisecond
	opts.WorkerIdleTTL = 1 * time.Second
	opts.SameHostOnly = true
	opts.MaxVisits = 20
	c := gocrawl.NewCrawlerWithOptions(opts)
	// Stop the crawler after 20 seconds
	t := time.NewTimer(10 * time.Second)
	defer t.Stop()
	go func() {
		<-t.C
		c.Stop()
	}()

	c.Run(fmt.Sprintf("%s/%s/%s", archiveItURL, year, sub))
	return ext.names
}
