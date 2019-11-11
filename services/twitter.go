// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package services

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/eventbus"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/dghubble/go-twitter/twitter"
	"golang.org/x/oauth2"
)

// Twitter is the Service that handles access to the Twitter data source.
type Twitter struct {
	BaseService

	API        *config.APIKey
	SourceType string
	client     *twitter.Client
}

// NewTwitter returns he object initialized, but not yet started.
func NewTwitter(sys System) *Twitter {
	t := &Twitter{SourceType: requests.API}

	t.BaseService = *NewBaseService(t, "Twitter", sys)
	return t
}

// Type implements the Service interface.
func (t *Twitter) Type() string {
	return t.SourceType
}

// OnStart implements the Service interface.
func (t *Twitter) OnStart() error {
	t.BaseService.OnStart()

	t.API = t.System().Config().GetAPIKey(t.String())
	if t.API == nil || t.API.Key == "" || t.API.Secret == "" {
		t.System().Config().Log.Printf("%s: API key data was not provided", t.String())
	} else {
		if bearer, err := t.getBearerToken(); err == nil {
			config := &oauth2.Config{}
			token := &oauth2.Token{AccessToken: bearer}
			// OAuth2 http.Client will automatically authorize Requests
			httpClient := config.Client(oauth2.NoContext, token)
			// Twitter client
			t.client = twitter.NewClient(httpClient)
		}
	}

	t.SetRateLimit(3 * time.Second)
	return nil
}

// OnDNSRequest implements the Service interface.
func (t *Twitter) OnDNSRequest(ctx context.Context, req *requests.DNSRequest) {
	cfg := ctx.Value(requests.ContextConfig).(*config.Config)
	bus := ctx.Value(requests.ContextEventBus).(*eventbus.EventBus)
	if cfg == nil || bus == nil {
		return
	}

	re := cfg.DomainRegex(req.Domain)
	if t.client == nil || re == nil {
		return
	}

	t.CheckRateLimit()
	bus.Publish(requests.SetActiveTopic, t.String())
	bus.Publish(requests.LogTopic, fmt.Sprintf("Querying %s for %s subdomains", t.String(), req.Domain))

	searchParams := &twitter.SearchTweetParams{
		Query: req.Domain,
		Count: 100,
	}
	search, _, err := t.client.Search.Tweets(searchParams)
	if err != nil {
		bus.Publish(requests.LogTopic, fmt.Sprintf("%s: %v", t.String(), err))
		return
	}

	for _, tweet := range search.Statuses {
		// URLs in the tweet body
		for _, urlEntity := range tweet.Entities.Urls {
			for _, name := range re.FindAllString(urlEntity.ExpandedURL, -1) {
				bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
					Name:   name,
					Domain: req.Domain,
					Tag:    t.SourceType,
					Source: t.String(),
				})
			}
		}

		// Source of the tweet
		for _, name := range re.FindAllString(tweet.Source, -1) {
			bus.Publish(requests.NewNameTopic, &requests.DNSRequest{
				Name:   name,
				Domain: req.Domain,
				Tag:    t.SourceType,
				Source: t.String(),
			})
		}
	}
}

func (t *Twitter) getBearerToken() (string, error) {
	headers := map[string]string{"Content-Type": "application/x-www-form-urlencoded;charset=UTF-8"}
	page, err := http.RequestWebPage(
		"https://api.twitter.com/oauth2/token",
		strings.NewReader("grant_type=client_credentials"),
		headers, t.API.Key, t.API.Secret)
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
