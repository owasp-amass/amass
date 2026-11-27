// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package sessions

import (
	"context"
	"log/slog"
	"strconv"
	"strings"
	"time"

	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	afmt "github.com/owasp-amass/amass/v5/internal/afmt"
	dbt "github.com/owasp-amass/asset-db/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// startRun records the session as a collection run: what it was asked to
// collect and how, so a later reader can tell what this enumeration did
// not find. A failure is logged; the enumeration goes on without it.
func (s *Session) startRun() {
	// a worker joining a job works under the job's run
	if s.runs == nil || s.joined {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	run, err := s.runs.StartRun(ctx, &dbt.CollectionRun{Tool: "amass", ToolVersion: afmt.Version,
		ExternalID: s.id.String(), StartedAt: s.start, Scope: runScope(s.cfg.Scope), Metadata: runMetadata(s.cfg)})
	if err != nil {
		s.engineLog().Error("failed to record the collection run", "err", err.Error())
		return
	}

	s.run = run.ID
}

// finishRun ends the session's run, and returns how: finished when all its
// work was done, stopped when it ended with work left, so a run cut short is
// never read as having looked everywhere.
func (s *Session) finishRun() string {
	if s.runs == nil || s.run == "" {
		return ""
	}

	status := dbt.RunStopped
	s.stats.RLock()
	if s.stats.WorkItemsTotal > 0 && s.stats.WorkItemsCompleted >= s.stats.WorkItemsTotal {
		status = dbt.RunFinished
	}

	s.stats.RUnlock()
	if s.stats.Background() > 0 {
		status = dbt.RunStopped
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	if _, err := s.runs.FinishRun(ctx, s.run, status, time.Time{}); err != nil {
		s.engineLog().Error("failed to finish the collection run", "run", s.run, "err", err.Error())
	}
	return status
}

// runScope names a configuration's scope as Open Asset Model targets.
func runScope(sc *config.Scope) []dbt.RunTarget {
	if sc == nil {
		return nil
	}

	var out []dbt.RunTarget
	for _, d := range sc.Domains {
		out = append(out, dbt.RunTarget{Type: oam.FQDN, Key: strings.ToLower(d)})
	}
	for _, ip := range sc.Addresses {
		out = append(out, dbt.RunTarget{Type: oam.IPAddress, Key: ip.String()})
	}
	for _, c := range sc.CIDRs {
		out = append(out, dbt.RunTarget{Type: oam.Netblock, Key: c.String()})
	}
	for _, asn := range sc.ASNs {
		out = append(out, dbt.RunTarget{Type: oam.AutonomousSystem, Key: strconv.Itoa(asn)})
	}

	return out
}

// runMetadata records how the enumeration collected.
func runMetadata(cfg *config.Config) map[string]any {
	mode := "default"
	switch {
	case cfg.Active:
		mode = "active"
	case cfg.Passive:
		mode = "passive"
	}

	return map[string]any{"mode": mode, "widens": cfg.Widens(), "brute_forcing": cfg.BruteForcing,
		"alterations": cfg.Alterations}
}

// Probe pacing defaults, in milliseconds: an active-enumeration probe to a
// host is held until at least defaultProbePaceMS has passed since the
// previous probe to that host, plus up to defaultProbeJitterMS of random
// spread. The default is modest so that, with many hosts probed at once, an
// enumeration keeps its pace while no single host sees a simultaneous burst
// across ports. The options "probe_pace_ms" and "probe_jitter_ms" override
// them, and a pace of 0 turns pacing off.
const (
	defaultProbePaceMS   = 500
	defaultProbeJitterMS = 1500
)

// probePacer builds a session's probe pacer from its configuration.
func probePacer(cfg *config.Config) *et.ProbePacer {
	pace := optionMS(cfg, "probe_pace_ms", defaultProbePaceMS)
	jitter := optionMS(cfg, "probe_jitter_ms", defaultProbeJitterMS)
	return et.NewProbePacer(time.Duration(pace)*time.Millisecond, time.Duration(jitter)*time.Millisecond)
}

// optionMS reads a non-negative millisecond option, falling back to def when
// it is absent or not a non-negative number.
func optionMS(cfg *config.Config, name string, def int) int {
	if cfg == nil || cfg.Options == nil {
		return def
	}

	switch v := cfg.Options[name].(type) {
	case int:
		if v >= 0 {
			return v
		}
	case int64:
		if v >= 0 {
			return int(v)
		}
	case float64:
		if v >= 0 {
			return int(v)
		}
	}

	return def
}

// netUsageMessage begins the log lines with a session's share of the
// engine's DNS queries and data source rate limits.
const netUsageMessage = "shared network use"

// netUsageEvery is how often a running session logs its shared network use,
// so sessions that run at the same time can be compared while they run.
var netUsageEvery = 10 * time.Minute

// engineLog is the engine's own log, which the engine writes to its
// configured destination (syslog in the Docker setup), with the session's
// ID; slog.Default writes to the engine's standard output.
func (s *Session) engineLog() *slog.Logger {
	l := slog.Default()
	if s.mgr != nil && s.mgr.logger != nil {
		l = s.mgr.logger
	}

	return l.With("session", s.id.String())
}

func (s *Session) logNetUsage() {
	tick := time.NewTicker(netUsageEvery)
	defer tick.Stop()

	for {
		select {
		case <-s.done:
			return
		case <-tick.C:
			s.netUsage.Log(s.engineLog(), netUsageMessage+" so far")
		}
	}
}
