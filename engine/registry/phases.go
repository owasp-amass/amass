// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"fmt"
	"slices"
	"sync"

	"github.com/caffix/pipeline"
	multierror "github.com/hashicorp/go-multierror"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

// Phase is a range of handler positions that a phased pipeline runs as one
// step. An ordered phase keeps a stage for each position, as the position
// pipeline does. In any other phase an event goes to every plugin's
// handlers at once, each plugin's own handlers still in position order, and
// moves on when all have finished.
type Phase struct {
	Name        string
	First, Last int
	Ordered     bool
}

// Phases are the steps of a phased pipeline. Resolve is ordered: the DNS
// handlers depend on each other, BGP.Tools, IP-Netblock and Team Cymru do,
// and DNS and Known-FQDN write the event metadata (e.Meta) that later
// handlers read. Every handler after it only reads that metadata.
var Phases = []Phase{
	{Name: "resolve", First: 1, Last: 11, Ordered: true},
	{Name: "collect", First: 12, Last: 39},
	{Name: "probe", First: 40, Last: 49},
	{Name: "derive", First: 50, Last: 50},
}

// phaseWidth is how many events a concurrent phase handles at once in one
// session's pipeline. Each handler is still bounded by its MaxInstances.
const phaseWidth = 100

// PhaseOf returns the name of the phase a handler position belongs to.
func PhaseOf(position int) string {
	position = min(max(position, 1), 50)
	for _, ph := range Phases {
		if position >= ph.First && position <= ph.Last {
			return ph.Name
		}
	}
	return ""
}

// BuildPhasedPipeline builds an asset type's pipeline from the phases: the
// resolve phase's position stages, then a stage for each concurrent phase.
func (r *registry) BuildPhasedPipeline(ctx context.Context, atype oam.AssetType) (*et.AssetPipeline, error) {
	var stages []pipeline.Stage

	bufsize := 1
	for _, ph := range Phases {
		if ph.Ordered {
			st, n := r.positionStages(atype, ph.First, ph.Last)
			stages = append(stages, st...)
			bufsize = max(bufsize, n)
			continue
		}

		if task := phaseTask(r.phaseRuns(atype, ph)); task != nil {
			id := fmt.Sprintf("%s - Phase: %s", atype, ph.Name)
			stages = append(stages, pipeline.DynamicPool(id, task, phaseWidth))
		}
	}

	return r.runPipeline(ctx, atype, stages, bufsize), nil
}

// limitedHandler is a handler with the slots that bound how many events it
// handles at once in one pipeline. Waiting senders on a channel are served
// in order, so the slots queue an event for a busy handler.
type limitedHandler struct {
	*et.Handler
	slots chan struct{}
}

func (h limitedHandler) handle(ctx context.Context, ede *et.EventDataElement) (bool, error) {
	select {
	case h.slots <- struct{}{}:
	case <-ctx.Done():
		return false, nil
	}
	defer func() { <-h.slots }()

	return handleElement(ctx, h.Handler, ede)
}

// phaseRuns returns, for each plugin with handlers in a phase, its handlers
// in position order, plugins ordered by their first handler.
func (r *registry) phaseRuns(atype oam.AssetType, ph Phase) [][]limitedHandler {
	var runs [][]limitedHandler
	index := map[et.Plugin]int{}

	for pos := ph.First; pos <= ph.Last; pos++ {
		for _, h := range r.handlers[atype][pos] {
			if h == nil || h.Callback == nil {
				continue
			}

			lh := limitedHandler{Handler: h, slots: make(chan struct{}, max(h.MaxInstances, 1))}
			if i, ok := index[h.Plugin]; ok {
				runs[i] = append(runs[i], lh)
				continue
			}
			index[h.Plugin] = len(runs)
			runs = append(runs, []limitedHandler{lh})
		}
	}

	return runs
}

// phaseTask returns the task of a concurrent phase: each plugin's handlers
// run in a goroutine of their own, in position order, and the event moves
// on when every plugin has finished. An event a handler reports done (the
// engine or the session ended) leaves the pipeline once, after the others.
func phaseTask(runs [][]limitedHandler) pipeline.TaskFunc {
	if len(runs) == 0 {
		return nil
	}

	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		ede, err := eventElement(runs[0][0].Handler, data)
		if err != nil {
			return nil, err
		}

		oks := make([]bool, len(runs))
		errs := make([][]error, len(runs))
		var wg sync.WaitGroup
		for i, run := range runs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				oks[i] = true
				for _, h := range run {
					ok, herr := h.handle(ctx, ede)
					if herr != nil {
						errs[i] = append(errs[i], herr)
					}
					if !ok {
						oks[i] = false
						return
					}
				}
			}()
		}

		wg.Wait()

		// the handlers have finished, so the event's errors are written
		// here alone
		for _, list := range errs {
			for _, err := range list {
				ede.Error = multierror.Append(ede.Error, err)
			}
		}
		if slices.Contains(oks, false) {
			sendElementOnExit(ctx, ede)
			return nil, nil
		}

		return data, nil
	})
}
