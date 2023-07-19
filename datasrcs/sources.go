// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package datasrcs

import (
	"sort"

	"github.com/caffix/service"
	"github.com/caffix/stringset"
	"github.com/owasp-amass/amass/v4/datasrcs/scripting"
	"github.com/owasp-amass/amass/v4/systems"
	"github.com/owasp-amass/config/config"
)

// GetAllSources returns a slice of all data source services initialized.
func GetAllSources(sys systems.System) []service.Service {
	var srvs []service.Service

	if scripts, err := sys.Config().AcquireScripts(); err == nil {
		for _, script := range scripts {
			if s := scripting.NewScript(script, sys); s != nil {
				srvs = append(srvs, s)
			}
		}
	}

	sort.Slice(srvs, func(i, j int) bool {
		return srvs[i].String() < srvs[j].String()
	})
	return srvs
}

// SelectedDataSources uses the config and available data sources to return the selected data sources.
func SelectedDataSources(cfg *config.Config, avail []service.Service) []service.Service {
	specified := stringset.New()
	defer specified.Close()
	specified.InsertMany(cfg.SourceFilter.Sources...)

	available := stringset.New()
	defer available.Close()
	for _, src := range avail {
		available.Insert(src.String())
	}

	if specified.Len() > 0 && cfg.SourceFilter.Include {
		available.Intersect(specified)
	} else {
		available.Subtract(specified)
	}

	var results []service.Service
	for _, src := range avail {
		if available.Has(src.String()) {
			results = append(results, src)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		return results[i].String() < results[j].String()
	})
	return results
}
