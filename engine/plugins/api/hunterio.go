// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package api

/*
import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"

	"github.com/owasp-amass/amass/v4/utils/net/http"
	"github.com/owasp-amass/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
	"github.com/owasp-amass/open-asset-model/contact"
	"github.com/owasp-amass/open-asset-model/domain"
	"github.com/owasp-amass/open-asset-model/source"
	"go.uber.org/ratelimit"
)

type hunterIO struct {
	name             string
	counturl         string
	queryurl         string
	emailVerifierurl string
	accounttype      string
	log              *slog.Logger
	rlimit           ratelimit.Limiter
	source           *source.Source
}

func NewHunterIO() et.Plugin {
	return &hunterIO{
		name:             "Hunter.io",
		counturl:         "https://api.hunter.io/v2/email-count?domain=",
		queryurl:         "https://api.hunter.io/v2/domain-search?domain=",
		emailVerifierurl: "https://api.hunter.io/v2/email-verifier?email=",
		rlimit:           ratelimit.New(15, ratelimit.WithoutSlack),
		source: &source.Source{
			Name:       "Hunter.io",
			Confidence: 80,
		},
	}
}

func (h *hunterIO) Name() string {
	return h.name
}

func (h *hunterIO) Start(r et.Registry) error {
	h.log = r.Log().WithGroup("plugin").With("name", h.name)

	name := h.name + "-Email-Generation-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     h,
		Name:       name,
		Transforms: []string{"emailaddress"},
		EventType:  oam.FQDN,
		Callback:   h.check,
	}); err != nil {
		return err
	}

	name = h.name + "-Email-Verification-Handler"
	if err := r.RegisterHandler(&et.Handler{
		Plugin:     h,
		Name:       name,
		Transforms: []string{"emailaddress"},
		EventType:  oam.EmailAddress,
		Callback:   h.verify,
	}); err != nil {
		return err
	}

	h.log.Info("Plugin started")
	return nil
}

func (h *hunterIO) Stop() {
	h.log.Info("Plugin stopped")
}

func (h *hunterIO) check(e *et.Event) error {
	fqdn, ok := e.Asset.Asset.(*domain.FQDN)
	if !ok {
		return errors.New("failed to extract the FQDN asset")
	}

	domlt := strings.ToLower(strings.TrimSpace(fqdn.Name))
	if e.Session.Config().WhichDomain(domlt) != domlt {
		return nil
	}

	src := support.GetSource(e.Session, h.source)
	if src == nil {
		return errors.New("failed to obtain the plugin source information")
	}

	h.rlimit.Take()
	if count, err := h.count(domlt); err != nil {
		e.Session.Log().Error(fmt.Sprintf("Failed to use the API count endpoint: %v", err),
			slog.Group("plugin", "name", h.name, "handler", h.name+"-Email-Generation-Handler"))
		return nil
	} else {
		api, err := h.account_type(e)
		if err != nil || api == "" {
			return nil
		}
		results, err := h.query(domlt, count, api)
		if err != nil {
			e.Session.Log().Error(fmt.Sprintf("Failed to query: %v", err),
				slog.Group("plugin", "name", h.name, "handler", h.name+"-Email-Generation-Handler"))
			return nil
		}
		support.ProcessEmailsWithSource(e, results, src)
	}
	return nil
}

func (h *hunterIO) verify(e *et.Event) error {
	email, ok := e.Asset.Asset.(*contact.EmailAddress)
	if !ok {
		return errors.New("failed to extract the EmailAddress asset")
	}

	h.rlimit.Take()
	api, err := support.GetAPI(h.name, e)
	if err != nil || api == "" {
		return nil
	}

	type responseJSON struct {
		Data struct {
			Status string `json:"status"`
			Result string `json:"result"`
		} `json:"data"`
	}

	var result responseJSON
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.emailVerifierurl + email.Address + "&api_key=" + api})
	if err != nil {
		e.Session.Log().Error(fmt.Sprintf("Failed to make Verify request: %v", err),
			slog.Group("plugin", "name", h.name, "handler", h.name+"-Email-Verification-Handler"))
		return nil
	}

	if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&result); err != nil {
		e.Session.Log().Error(fmt.Sprintf("Failed to decode JSON: %v", err),
			slog.Group("plugin", "name", h.name, "handler", h.name+"-Email-Verification-Handler"))
		return nil
	}

	eventMeta, ok := e.Meta.(*et.EmailMeta)
	if !ok {
		if e.Meta != nil {
			return fmt.Errorf("unexpected Meta type: %T", e.Meta)
		}
		return nil
	}
	eventMeta.VerifyAttempted = true

	if result.Data.Status != "unknown" && result.Data.Status != "invalid" &&
		result.Data.Status != "disposable" && result.Data.Status != "accept_all" {
		eventMeta.Verified = true
	}
	return nil
}

func (h *hunterIO) account_type(e *et.Event) (string, error) {
	api, err := support.GetAPI(h.name, e)
	if err != nil || api == "" {
		return "", err
	}

	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: "https://api.hunter.io/v2/account?api_key=" + api})
	if err != nil {
		return "", err
	}

	// make a struct to hold the response since it returns as json
	type responseJSON struct {
		Data struct {
			Plan string `json:"plan_name"`
		} `json:"data"`
	}

	var response responseJSON
	// decode the json then return the total only
	if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
		return "", err
	}
	h.accounttype = response.Data.Plan
	return api, nil
}

func (h *hunterIO) count(domain string) (int, error) {
	resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.counturl + domain})
	if err != nil {
		return 0, err
	}

	// make a struct to hold the response since it returns as json
	type responseJSON struct {
		Data struct {
			Total int `json:"total"`
		} `json:"data"`
	}

	var response responseJSON
	// decode the json then return the total only
	if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
		return 0, err
	}
	return response.Data.Total, nil

}

func (h *hunterIO) query(domain string, count int, api string) ([]string, error) {
	var result []string
	// make a struct to hold the response since it returns as json
	type responseJSON struct {
		Data struct {
			Email []struct {
				Value string `json:"value"`
			} `json:"emails"`
		} `json:"data"`
	}

	var response responseJSON
	// if the count is less than or equal to 10, we can get all the emails in one request
	// TODO: add another condition for free API keys, since they could only get the first ten anyways.
	if count <= 10 || h.accounttype == "Free" {
		resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.queryurl + domain + "&api_key=" + api})
		if err != nil {
			return nil, err
		}
		if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
			return nil, err
		}
		for _, data := range response.Data.Email {
			result = append(result, data.Value)
		}

	} else {
		for offset := 0; offset < count; offset += 100 {
			resp, err := http.RequestWebPage(context.TODO(), &http.Request{URL: h.queryurl + domain + "&api_key=" + api + "&limit=100&offset=" + strconv.Itoa(offset)})
			if err != nil && resp.StatusCode != 400 {
				return nil, err
			} else if resp.StatusCode == 400 { // since the API returns 400 when the limit is exceeded or if any error occurs, we break the loop
				break
			}
			if err := json.NewDecoder(strings.NewReader(resp.Body)).Decode(&response); err != nil {
				return nil, err
			}
			for _, data := range response.Data.Email {
				result = append(result, data.Value)
			}

		}
	}

	return result, nil
}
*/
