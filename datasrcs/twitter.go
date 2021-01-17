// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package datasrcs

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/OWASP/Amass/v3/systems"
	"github.com/caffix/eventbus"
	"github.com/caffix/service"
	"github.com/dghubble/go-twitter/twitter"
	"golang.org/x/oauth2"
)

// Twitter is the Service that handles access to the Twitter data source.
type Twitter struct {
	service.BaseService

	SourceType string
	sys        systems.System
	creds      *config.Credentials
	client     *twitter.Client
}

// NewTwitter returns he object initialized, but not yet started.
func NewTwitter(sys systems.System) *Twitter {
	t := &Twitter{
		SourceType: requests.API,
		sys:        sys,
	}

	t.BaseService = *service.NewBaseService(t, "Twitter")
	return t
}

// Description implements the Service interface.
func (t *Twitter) Description() string {
	return t.SourceType
}

// OnStart implements the Service interface.
func (t *Twitter) OnStart() error {
	t.creds = t.sys.Config().GetDataSourceConfig(t.String()).GetCredentials()

	if t.creds == nil || t.creds.Key == "" || t.creds.Secret == "" {
		t.sys.Config().Log.Printf("%s: API key data was not provided", t.String())
	} else {
		if bearer, err := t.getBearerToken(); err == nil {
			config := &oauth2.Config{}
			token := &oauth2.Token{AccessToken: bearer}
			// OAuth2 http.Client will automatically authorize Requests
			httpClient := config.Client(context.Background(), token)
			// Twitter client
			t.client = twitter.NewClient(httpClient)
		}
	}

	t.SetRateLimit(1)
	return t.checkConfig()
}

// CheckConfig implements the Service interface.
func (t *Twitter) checkConfig() error {
	creds := t.sys.Config().GetDataSourceConfig(t.String()).GetCredentials()

	if creds == nil || creds.Key == "" || creds.Secret == "" {
		estr := fmt.Sprintf("%s: check callback failed for the configuration", t.String())
		t.sys.Config().Log.Print(estr)
		return errors.New(estr)
	}

	return nil
}

// OnRequest implements the Service interface.
func (t *Twitter) OnRequest(ctx context.Context, args service.Args) {
	if req, ok := args.(*requests.DNSRequest); ok {
		t.dnsRequest(ctx, req)
	}
}

func (t *Twitter) dnsRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg, bus, err := ContextConfigBus(ctx)
	if err != nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if t.client == nil || re == nil {
		return
	}

	numRateLimitChecks(t, 2)
	bus.Publish(requests.LogTopic, eventbus.PriorityHigh,
		fmt.Sprintf("Querying %s for %s subdomains", t.String(), req.Domain))

	searchParams := &twitter.SearchTweetParams{
		Query: req.Domain,
		Count: 100,
	}
	search, _, err := t.client.Search.Tweets(searchParams)
	if err != nil {
		bus.Publish(requests.LogTopic, eventbus.PriorityHigh, fmt.Sprintf("%s: %v", t.String(), err))
		return
	}

	for _, tweet := range search.Statuses {
		// URLs in the tweet body
		for _, urlEntity := range tweet.Entities.Urls {
			for _, name := range re.FindAllString(urlEntity.ExpandedURL, -1) {
				genNewNameEvent(ctx, t.sys, t, name)
			}
		}

		// Source of the tweet
		for _, name := range re.FindAllString(tweet.Source, -1) {
			genNewNameEvent(ctx, t.sys, t, name)
		}
	}
}

func (t *Twitter) getBearerToken() (string, error) {
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
	page, err := http.RequestWebPage(
		"https://api.twitter.com/oauth2/token",
		strings.NewReader("grant_type=client_credentials"),
		headers, t.creds.Key, t.creds.Secret)
	if err != nil {
		return "", fmt.Errorf("token request failed: %+v", err)
	}

	var v struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.Unmarshal([]byte(page), &v); err != nil {
		return "", fmt.Errorf("error parsing json in token response: %+v", err)
	}
	if v.AccessToken == "" {
		return "", fmt.Errorf("token response does not have access_token")
	}
	return v.AccessToken, nil
}
