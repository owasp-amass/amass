// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

// Package reputation matches the IP addresses and netblocks an enumeration
// reaches against keyless reputation feeds (semantics
// reputation_feeds.json) and records each listing as the asset's
// reputation_listing property. A listing describes the address, not who
// runs it, so it is never ownership evidence.
package reputation

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/owasp-amass/amass/v5/engine/plugins/support"
	et "github.com/owasp-amass/amass/v5/engine/types"
	amassnet "github.com/owasp-amass/amass/v5/internal/net"
	"github.com/owasp-amass/amass/v5/internal/semantics"
	oam "github.com/owasp-amass/open-asset-model"
	oamnet "github.com/owasp-amass/open-asset-model/network"
	"github.com/yl2chen/cidranger"
)

// PropListing is the property a listed asset gets: the feed's name.
const PropListing = semantics.ReputationListingProperty

// downloadTimeout bounds one feed download.
const downloadTimeout = 2 * time.Minute

// feed is one downloaded feed's ranges.
type feed struct {
	semantics.ReputationFeed
	path   string
	loaded time.Time // the file's modification time when it was read
	ranger cidranger.Ranger
}

type reputation struct {
	name    string
	log     *slog.Logger
	source  *et.Source
	catalog semantics.ReputationFeeds
	dir     string

	mu    sync.Mutex
	feeds []*feed
}

func NewReputation() et.Plugin {
	c := semantics.ReputationFeedCatalog()
	dir := filepath.Join(os.TempDir(), "amass-reputation")
	return &reputation{
		name:    "Reputation-Feeds",
		source:  &et.Source{Name: "Reputation-Feeds", Confidence: 80},
		catalog: c,
		dir:     dir,
		feeds:   newFeeds(c, dir),
	}
}

// newFeeds are the catalog's feeds, each kept in its own file under dir.
func newFeeds(c semantics.ReputationFeeds, dir string) []*feed {
	var out []*feed
	for _, f := range c.Feeds {
		sum := sha256.Sum256([]byte(f.URL))
		out = append(out, &feed{ReputationFeed: f, path: filepath.Join(dir, hex.EncodeToString(sum[:8]))})
	}
	return out
}

func (r *reputation) Name() string { return r.name }

func (r *reputation) Start(reg et.Registry) error {
	r.log = reg.Log().WithGroup("plugin").With("name", r.name)

	for _, h := range []struct {
		name  string
		atype oam.AssetType
		check func(*et.Event) error
	}{{"IP", oam.IPAddress, r.checkAddress}, {"Netblock", oam.Netblock, r.checkNetblock}} {
		if err := reg.RegisterHandler(&et.Handler{
			Plugin:       r,
			Name:         r.name + "-" + h.name + "-Handler",
			Position:     2,
			MaxInstances: support.MidHandlerInstances,
			Transforms:   []string{string(h.atype)},
			EventType:    h.atype,
			Callback:     h.check,
		}); err != nil {
			return err
		}
	}

	r.log.Info("Plugin started")
	return nil
}

func (r *reputation) Stop() { r.log.Info("Plugin stopped") }

func (r *reputation) checkAddress(e *et.Event) error {
	ip, ok := e.Entity.Asset.(*oamnet.IPAddress)
	if !ok || !ip.Address.IsValid() {
		return nil
	}
	addr := net.IP(ip.Address.AsSlice())
	r.record(e, func(rg cidranger.Ranger) bool {
		in, err := rg.Contains(addr)
		return err == nil && in
	})
	return nil
}

func (r *reputation) checkNetblock(e *et.Event) error {
	nb, ok := e.Entity.Asset.(*oamnet.Netblock)
	if !ok || !nb.CIDR.IsValid() {
		return nil
	}
	_, block, err := net.ParseCIDR(nb.CIDR.String())
	if err != nil {
		return nil
	}
	// listed when a listed range holds the netblock or lies inside it
	r.record(e, func(rg cidranger.Ranger) bool {
		if holders, err := rg.ContainingNetworks(block.IP); err == nil {
			for _, h := range holders {
				if n := h.Network(); covers(&n, block) {
					return true
				}
			}
		}
		inside, err := rg.CoveredNetworks(*block)
		return err == nil && len(inside) > 0
	})
	return nil
}

// covers reports whether outer holds all of inner.
func covers(outer, inner *net.IPNet) bool {
	o, _ := outer.Mask.Size()
	i, _ := inner.Mask.Size()
	return outer.Contains(inner.IP) && o <= i
}

// record adds the reputation_listing property of every feed whose ranges
// listed says hold the event's asset.
func (r *reputation) record(e *et.Event, listed func(cidranger.Ranger) bool) {
	ctx, cancel := context.WithTimeout(e.Session.Ctx(), 10*time.Second)
	defer cancel()

	done := map[string]bool{}
	for _, f := range r.ready(e) {
		if !done[f.Name] && listed(f.ranger) {
			done[f.Name] = true
			support.AddProperty(ctx, e.Session, e.Entity, PropListing, f.Name)
		}
	}
}

// ready refreshes the feeds whose downloads are older than their refresh
// period, rereads any whose file changed, and returns those with ranges.
func (r *reputation) ready(e *et.Event) []*feed {
	r.mu.Lock()
	defer r.mu.Unlock()

	_ = os.MkdirAll(r.dir, 0o755)
	var out []*feed
	for _, f := range r.feeds {
		ttl := time.Duration(f.RefreshHours) * time.Hour
		if err := support.CachedDownload(e, f.URL, f.path, ttl, downloadTimeout, r.catalog.MaxBytes); err != nil &&
			f.ranger == nil {
			continue
		}
		if fi, err := os.Stat(f.path); err == nil && fi.ModTime().After(f.loaded) {
			if data, err := os.ReadFile(f.path); err == nil {
				f.ranger, f.loaded = parseFeed(f.Format, data), fi.ModTime()
			}
		}
		if f.ranger != nil {
			out = append(out, f)
		}
	}
	return out
}

// parseFeed reads a feed's ranges, skipping reserved and private ones.
func parseFeed(format string, data []byte) cidranger.Ranger {
	rg := cidranger.NewPCTrieRanger()
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 64*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if format == semantics.FeedNDJSONCIDR {
			var entry struct {
				CIDR string `json:"cidr"`
			}
			if json.Unmarshal([]byte(line), &entry) != nil {
				continue
			}
			line = entry.CIDR
		}
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if n := listedRange(line); n != nil {
			_ = rg.Insert(cidranger.NewBasicRangerEntry(*n))
		}
	}
	return rg
}

// listedRange parses an address or range a feed lists, or nil when it is
// malformed, reserved or private.
func listedRange(s string) *net.IPNet {
	if !strings.Contains(s, "/") {
		ip := net.ParseIP(s)
		if ip == nil {
			return nil
		}
		bits := 128
		if ip.To4() != nil {
			ip, bits = ip.To4(), 32
		}
		s = (&net.IPNet{IP: ip, Mask: net.CIDRMask(bits, bits)}).String()
	}
	_, n, err := net.ParseCIDR(s)
	if err != nil {
		return nil
	}
	if reserved, _ := amassnet.IsReservedAddress(n.IP.String()); reserved {
		return nil
	}
	return n
}
