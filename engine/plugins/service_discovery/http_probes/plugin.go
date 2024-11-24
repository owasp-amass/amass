// Copyright © by Jeff Foley 2017-2024. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package http_probes

import (
	"hash/maphash"
	"log/slog"

	"github.com/owasp-amass/amass/v4/engine/plugins/support"
	et "github.com/owasp-amass/amass/v4/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

type httpProbing struct {
	name    string
	log     *slog.Logger
	fqdnend *fqdnEndpoint
	ipaddr  *ipaddrEndpoint
	interr  *interrogation
	source  *et.Source
	hash    maphash.Hash
}

func NewHTTPProbing() et.Plugin {
	return &httpProbing{
		name: "HTTP-Probes",
		source: &et.Source{
			Name:       "HTTP-Probes",
			Confidence: 100,
		},
	}
}

func (hp *httpProbing) Name() string {
	return hp.name
}

func (hp *httpProbing) Start(r et.Registry) error {
	hp.hash.SetSeed(maphash.MakeSeed())
	hp.log = r.Log().WithGroup("plugin").With("name", hp.name)

	hp.fqdnend = &fqdnEndpoint{
		name:   hp.name + "-FQDN-Endpoint-Handler",
		plugin: hp,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hp,
		Name:         hp.fqdnend.name,
		Priority:     9,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.NetworkEndpoint)},
		EventType:    oam.FQDN,
		Callback:     hp.fqdnend.check,
	}); err != nil {
		return err
	}

	hp.ipaddr = &ipaddrEndpoint{
		name:   hp.name + "-IPAddress-Endpoint-Handler",
		plugin: hp,
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hp,
		Name:         hp.ipaddr.name,
		Priority:     9,
		MaxInstances: support.MaxHandlerInstances,
		Transforms:   []string{string(oam.SocketAddress)},
		EventType:    oam.IPAddress,
		Callback:     hp.ipaddr.check,
	}); err != nil {
		return err
	}

	hp.interr = &interrogation{
		name:   hp.name + "-Interrogation",
		plugin: hp,
		transforms: []string{
			string(oam.Service),
			string(oam.TLSCertificate),
		},
		gate: make(map[string]struct{}),
	}
	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hp,
		Name:         hp.interr.name + "-NetworkEndpoint",
		MaxInstances: support.MaxHandlerInstances / 2,
		Transforms:   hp.interr.transforms,
		EventType:    oam.NetworkEndpoint,
		Callback:     hp.interr.check,
	}); err != nil {
		return err
	}

	if err := r.RegisterHandler(&et.Handler{
		Plugin:       hp,
		Name:         hp.interr.name + "-SocketAddress",
		MaxInstances: support.MaxHandlerInstances / 2,
		Transforms:   hp.interr.transforms,
		EventType:    oam.SocketAddress,
		Callback:     hp.interr.check,
	}); err != nil {
		return err
	}

	hp.log.Info("Plugin started")
	return nil
}

func (hp *httpProbing) Stop() {
	hp.log.Info("Plugin stopped")
}
