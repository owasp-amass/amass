// Copyright 2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	jsoniter "github.com/json-iterator/go"
	"strings"
)

// FOFA is the Service that handles access to the FOFA data source.
type FOFA struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
}

type fofaResponse struct {
	Error   bool     `json:"error"`
	ErrMsg  string   `json:"errmsg"`
	Size    int      `json:"size"`
	Results []string `json:"results"`
}

// NewFOFA returns he object initialized, but not yet started.
func NewFOFA(sys systems.System) *FOFA {
	f := &FOFA{
		SourceType: requests.SCRAPE,
		sys:        sys,
	}

	f.BaseService = *service.NewBaseService(f, "FOFA")
	return f
}

// Description implements the Service interface.
func (f *FOFA) Description() string {
	return f.SourceType
}

// OnStart implements the Service interface.
func (f *FOFA) OnStart() error {
	f.creds = f.sys.Config().GetDataSourceConfig(f.String()).GetCredentials()
	if f.creds == nil || f.creds.Username == "" || f.creds.Key == "" {
		estr := fmt.Sprintf("%s: Email address or API key data was not provided", f.String())

		f.sys.Config().Log.Print(estr)
		return errors.New(estr)
	}

	f.SetRateLimit(1)
	return nil
}

// OnRequest implements the Service interface.
func (f *FOFA) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		f.dnsRequest(ctx, req)
		f.CheckRateLimit()
	}
}

func (f *FOFA) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := requests.ContextConfigBus(ctx)
	if err != nil {
		return
	}

	if f.creds == nil || f.creds.Username == "" || f.creds.Key == "" {
		return
	}

	if !cfg.IsDomainInScope(req.Domain) {
		return
	}

	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", f.String(), req.Domain))

	// fofa api doc https://fofa.so/static_pages/api_help
	qbase64 := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("domain=\"%s\"", req.Domain)))

	headers := map[string]string{"Content-Type": "application/json"}

	var flag = true
	for i := 1; i <= 10; i++ {
		if !flag {
			break
		}
		url := f.getURL(qbase64, i)
		page, err := http.RequestWebPage(ctx, url, nil, headers, nil)

		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", f.String(), err))
			return
		}

		var response fofaResponse

		err = jsoniter.NewDecoder(strings.NewReader(page)).Decode(&response)
		if err != nil {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", f.String(), err))
			return
		}

		if response.Error {
			bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", f.String(), err))
			return
		}

		// 如果 size 小于 100 ，说明结果就一页，循环一次就行
		// 如果 len(response.Results) == 0， 说明当前循环的页数，超过了结果个数，下次就不进行了请求了
		if response.Size < 100 || len(response.Results) == 0 {
			flag = false
		}

		for _, subdomain := range response.Results {
			if strings.HasPrefix(strings.ToLower(subdomain), "http://") || strings.HasPrefix(strings.ToLower(subdomain), "https://") {
				subdomain = subdomain[strings.Index(subdomain, "//")+2:]
			}
			genNewNameEvent(ctx, f.sys, f, subdomain)
		}

		f.CheckRateLimit()
	}

}

func (f *FOFA) getURL(qbase64 string, page int) string {
	return fmt.Sprintf("https://fofa.so/api/v1/search/all?full=true&fields=host&page=%d&size=100&email=%s&key=%s&qbase64=%s", page, f.creds.Username, f.creds.Key, qbase64)
}
