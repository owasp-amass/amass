// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package sources

import (
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/config"
	eb "github.com/OWASP/Amass/eventbus"
	"github.com/OWASP/Amass/requests"
	"github.com/OWASP/Amass/resolvers"
	"github.com/OWASP/Amass/services"
	"github.com/OWASP/Amass/utils"
)

// DNSDumpster is the Service that handles access to the DNSDumpster data source.
type DNSDumpster struct {
	services.BaseService

	SourceType string
}

// NewDNSDumpster returns he object initialized, but not yet started.
func NewDNSDumpster(cfg *config.Config, bus *eb.EventBus, pool *resolvers.ResolverPool) *DNSDumpster {
	d := &DNSDumpster{SourceType: requests.SCRAPE}

	d.BaseService = *services.NewBaseService(d, "DNSDumpster", cfg, bus, pool)
	return d
}

// OnStart implements the Service interface
func (d *DNSDumpster) OnStart() error {
	d.BaseService.OnStart()

	go d.processRequests()
	return nil
}

func (d *DNSDumpster) processRequests() {
	for {
		select {
		case <-d.Quit():
			return
		case req := <-d.DNSRequestChan():
			if d.Config().IsDomainInScope(req.Domain) {
				d.executeQuery(req.Domain)
			}
		case <-d.AddrRequestChan():
		case <-d.ASNRequestChan():
		case <-d.WhoisRequestChan():
		}
	}
}

func (d *DNSDumpster) executeQuery(domain string) {
	re := d.Config().DomainRegex(domain)
	if re == nil {
		return
	}

	d.SetActive()
	u := "https://dnsdumpster.com/"
	page, err := utils.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		d.Config().Log.Printf("%s: %s: %v", d.String(), u, err)
		return
	}

	token := d.getCSRFToken(page)
	if token == "" {
		d.Config().Log.Printf("%s: %s: Failed to obtain the CSRF token", d.String(), u)
		return
	}

	d.SetActive()
	page, err = d.postForm(token, domain)
	if err != nil {
		d.Config().Log.Printf("%s: %s: %v", d.String(), u, err)
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		d.Bus().Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: domain,
			Tag:    d.SourceType,
			Source: d.String(),
		})
	}
}

func (d *DNSDumpster) getCSRFToken(page string) string {
	re := regexp.MustCompile("<input type='hidden' name='csrfmiddlewaretoken' value='([a-zA-Z0-9]*)' />")

	if subs := re.FindStringSubmatch(page); len(subs) == 2 {
		return strings.TrimSpace(subs[1])
	}
	return ""
}

func (d *DNSDumpster) postForm(token, domain string) (string, error) {
	dial := net.Dialer{}
	client := &http.Client{
		Transport: &http.Transport{
			DialContext:         dial.DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		},
	}
	params := url.Values{
		"csrfmiddlewaretoken": {token},
		"targetip":            {domain},
	}

	req, err := http.NewRequest("POST", "https://dnsdumpster.com/", strings.NewReader(params.Encode()))
	if err != nil {
		d.Config().Log.Printf("%s: Failed to setup the POST request: %v", d.String(), err)
		return "", err
	}
	// The CSRF token needs to be sent as a cookie
	cookie := &http.Cookie{
		Name:   "csrftoken",
		Domain: "dnsdumpster.com",
		Value:  token,
	}
	req.AddCookie(cookie)

	req.Header.Set("User-Agent", utils.UserAgent)
	req.Header.Set("Accept", utils.Accept)
	req.Header.Set("Accept-Language", utils.AcceptLang)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://dnsdumpster.com")
	req.Header.Set("X-CSRF-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		d.Config().Log.Printf("%s: The POST request failed: %v", d.String(), err)
		return "", err
	}
	// Now, grab the entire page
	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in), nil
}
