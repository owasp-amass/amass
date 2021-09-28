// Copyright 2017-2021 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package main

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/OWASP/Amass/v3/config"
	"github.com/OWASP/Amass/v3/enum"
	amassnet "github.com/OWASP/Amass/v3/net"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/caffix/netmap"
	"github.com/caffix/stringset"
	"github.com/fatih/color"
)

var endpoints = map[string][]string{
	"SecurityTrails": {"APIKEY", "https://api.securitytrails.com/v1/submit/hostnames?format=amass"},
	"WhoisXMLAPI":    {"X-Authentication-Token", "https://data-exchange.whoisxmlapi.com/data-exchange/1.0/amass/"},
}

type findings struct {
	Mode       string    `json:"mode"`
	AssetCount int       `json:"asset_count"`
	Domains    []*domain `json:"domains"`
}

type domain struct {
	Domain string   `json:"domain"`
	Assets []*asset `json:"assets"`
}

type asset struct {
	FQDN        string     `json:"fqdn"`
	SourceCount int        `json:"source_count"`
	SourceTypes []string   `json:"source_types"`
	Addrs       []*address `json:"addrs"`
}

type address struct {
	Address string  `json:"address"`
	Version string  `json:"version"`
	Ports   []*port `json:"ports"`
}

type port struct {
	Port int    `json:"port"`
	Jarm string `json:"jarm"`
}

func shareFindings(e *enum.Enumeration, cfg *config.Config) {
	dscfgs := participatingDataSources(cfg)
	if len(dscfgs) == 0 {
		return
	}

	fmt.Fprintf(color.Error, "%s\n", yellow("Formatting enumeration findings for sharing"))

	f := buildSharedData(e, cfg)
	if f == nil {
		return
	}

	j, err := json.Marshal(f)
	if err != nil {
		return
	}

	fmt.Fprintf(color.Error, "%s\n", yellow("Sharing enumeration findings"))

	for ds, info := range endpoints {
		var buf bytes.Buffer

		zw := gzip.NewWriter(&buf)
		zw.Name = "share.json"
		zw.Comment = "OWASP Amass enumeration findings"
		zw.ModTime = time.Now()
		if n, err := zw.Write(j); err != nil || n != len(j) || zw.Close() != nil {
			fmt.Fprintf(color.Error, "%s%s: %s\n", red("Failed to create the gzip file for "), red(ds), red(err.Error()))
			continue
		}

		if creds := dscfgs[ds].GetCredentials(); creds != nil {
			if err := sendFindings(info[1], &buf, info[0], creds.Key); err != nil {
				fmt.Fprintf(color.Error, "%s%s: %s\n", red("Failed to share findings with "), red(ds), red(err.Error()))
			}
		}
	}
}

func sendFindings(url string, data io.Reader, hdr, key string) error {
	headers := map[string]string{
		"Content-Encoding": "gzip",
		hdr:                key,
	}

	_, err := http.RequestWebPage(context.Background(), url, data, headers, nil)
	return err
}

func participatingDataSources(cfg *config.Config) map[string]*config.DataSourceConfig {
	dscfgs := make(map[string]*config.DataSourceConfig)

	for name := range endpoints {
		if c := cfg.GetDataSourceConfig(name); c != nil {
			dscfgs[name] = c
		}
	}

	return dscfgs
}

func buildSharedData(e *enum.Enumeration, cfg *config.Config) *findings {
	uuid := e.Config.UUID.String()

	f := &findings{Mode: "normal"}
	if e.Config.Passive {
		f.Mode = "passive"
	}
	if e.Config.Active {
		f.Mode = "active"
	}

	for _, d := range e.Graph.EventDomains(context.TODO(), uuid) {
		if !e.Config.IsDomainInScope(d) {
			continue
		}

		if n, err := e.Graph.ReadNode(context.TODO(), d, netmap.TypeFQDN); err == nil {
			s := &domain{
				Domain: d,
				Assets: getDomainAssets(e, n),
			}

			f.Domains = append(f.Domains, s)
			f.AssetCount += len(s.Assets)
		}
	}

	return f
}

func getDomainAssets(e *enum.Enumeration, dnode netmap.Node) []*asset {
	var assets []*asset

	edges, err := e.Graph.ReadInEdges(context.TODO(), dnode, "root")
	if err != nil {
		return assets
	}

	names := []string{e.Graph.NodeToID(dnode)}
	for _, edge := range edges {
		if name := e.Graph.NodeToID(edge.From); name != "" {
			names = append(names, name)
		}
	}

	for _, name := range names {
		if a := buildAssetInfo(e, name); a != nil {
			assets = append(assets, a)
		}
	}

	if e.Config.Passive {
		return assets
	}

	pairs, err := e.Graph.NamesToAddrs(context.TODO(), e.Config.UUID.String(), names...)
	if err != nil {
		return assets
	}

	addrmap := make(map[string][]*address, len(names))
	for _, pair := range pairs {
		addr := &address{
			Address: pair.Addr,
			Version: "ipv4",
		}

		if ip := net.ParseIP(pair.Addr); ip != nil {
			if amassnet.IsIPv6(ip) {
				addr.Version = "ipv6"
			}

			addrmap[pair.Name] = append(addrmap[pair.Name], addr)
		}
	}

	for _, asset := range assets {
		asset.Addrs = addrmap[asset.FQDN]
	}

	return assets
}

func buildAssetInfo(e *enum.Enumeration, sub string) *asset {
	a := &asset{FQDN: sub}
	if !e.Config.IsDomainInScope(a.FQDN) {
		return nil
	}

	sources, err := e.Graph.NodeSources(context.TODO(), sub, e.Config.UUID.String())
	if err != nil {
		return nil
	}

	var count int
	tags := stringset.New()
	defer tags.Close()

	for _, source := range sources {
		count++

		if tag, found := sourceTags[source]; found {
			tags.Insert(tag)
		}
	}

	a.SourceCount = count
	a.SourceTypes = tags.Slice()
	return a
}
