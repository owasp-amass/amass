// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/PuerkitoBio/gocrawl"
	"github.com/PuerkitoBio/goquery"
	"github.com/caffix/amass/amass/internal/utils"
)

type Query func(domain, sub string, l *log.Logger) []string

type ext struct {
	*gocrawl.DefaultExtender
	source          string
	domainRE        *regexp.Regexp
	mementoRE       *regexp.Regexp
	filter          map[string]bool
	flock           sync.RWMutex
	base, year, sub string
	names           []string
	logger          *log.Logger
}

func init() {
	// Modify the crawler's http client to use our DialContext
	gocrawl.HttpClient.Transport = &http.Transport{
		DialContext:           utils.DialContext,
		MaxIdleConns:          200,
		IdleConnTimeout:       5 * time.Second,
		TLSHandshakeTimeout:   5 * time.Second,
		ExpectContinueTimeout: 5 * time.Second,
	}
}

func (e *ext) reducedURL(u *url.URL) string {
	orig := u.String()

	idx := e.mementoRE.FindStringIndex(orig)
	if idx == nil {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s", e.base, e.year, orig[idx[1]:])
}

func (e *ext) Log(logFlags gocrawl.LogFlags, msgLevel gocrawl.LogFlags, msg string) {
	e.logger.Printf("%s error: %s", e.source, msg)
	return
}

func (e *ext) RequestRobots(ctx *gocrawl.URLContext, robotAgent string) (data []byte, doRequest bool) {
	return nil, false
}

func (e *ext) Filter(ctx *gocrawl.URLContext, isVisited bool) bool {
	if isVisited {
		return false
	}

	u := ctx.URL().String()
	r := e.reducedURL(ctx.URL())
	if !strings.Contains(ctx.URL().Path, e.sub) {
		return false
	}

	e.flock.RLock()
	_, ok := e.filter[r]
	e.flock.RUnlock()
	if ok {
		return false
	}

	if u != r {
		// The more refined version has been requested
		// and will cause the reduced version to be filtered
		e.flock.Lock()
		e.filter[r] = true
		e.flock.Unlock()
	}
	return true
}

func (e *ext) Visit(ctx *gocrawl.URLContext, res *http.Response, doc *goquery.Document) (interface{}, bool) {
	in, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, true
	}

	for _, f := range e.domainRE.FindAllString(string(in), -1) {
		e.names = utils.UniqueAppend(e.names, f)
	}
	return nil, true
}
