// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"fmt"
	"io/ioutil"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	amasshttp "github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
)

// DNSDumpster is the Service that handles access to the DNSDumpster data source.
type DNSDumpster struct {
	BaseService

	SourceType string
}

// NewDNSDumpster returns he object initialized, but not yet started.
func NewDNSDumpster(sys System) *DNSDumpster {
	d := &DNSDumpster{SourceType: requests.SCRAPE}

	d.BaseService = *NewBaseService(d, "DNSDumpster", sys)
	return d
}

// Type implements the Service interface.
func (d *DNSDumpster) Type() string {
	return d.SourceType
}

// OnStart implements the Service interface.
func (d *DNSDumpster) OnStart() error {
	d.BaseService.OnStart()

	d.SetRateLimit(time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (d *DNSDumpster) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if re == nil {
		return
	}

	d.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, d.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", d.String(), req.Domain))

	u := "https://dnsdumpster.com/"
	page, err := amasshttp.RequestWebPage(u, nil, nil, "", "")
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), u, err))
		return
	}

	token := d.getCSRFToken(page)
	if token == "" {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: Failed to obtain the CSRF token", d.String(), u))
		return
	}

	d.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, d.String())

	page, err = d.postForm(ctx, token, req.Domain)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %s: %v", d.String(), u, err))
		return
	}

	for _, sd := range re.FindAllString(page, -1) {
		bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
			Name:   cleanName(sd),
			Domain: req.Domain,
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

func (d *DNSDumpster) postForm(ctx context.Context, token, domain string) (string, error) {
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if bus == nil {
		return "", fmt.Errorf("%s failed to obtain the EventBus from Context", d.String())
	}

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
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: Failed to setup the POST request: %v", d.String(), err))
		return "", err
	}
	// The CSRF token needs to be sent as a cookie
	cookie := &http.Cookie{
		Name:   "csrftoken",
		Domain: "dnsdumpster.com",
		Value:  token,
	}
	req.AddCookie(cookie)

	req.Header.Set("User-Agent", amasshttp.UserAgent)
	req.Header.Set("Accept", amasshttp.Accept)
	req.Header.Set("Accept-Language", amasshttp.AcceptLang)
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://dnsdumpster.com")
	req.Header.Set("X-CSRF-Token", token)

	resp, err := client.Do(req)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: The POST request failed: %v", d.String(), err))
		return "", err
	}
	// Now, grab the entire page
	in, err := ioutil.ReadAll(resp.Body)
	resp.Body.Close()
	return string(in), nil
}
