// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/InfluxCommunity/influxdb3-go/v2/influxdb3"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
	oam "github.com/owasp-amass/open-asset-model"
)

var (
	dataPointQueue queue.Queue
	influxClient   *influxdb3.Client
)

func init() {
	var err error

	dataPointQueue = queue.NewQueue()
	// Create a new client using INFLUX_* environment variables.
	influxClient, err = influxdb3.NewFromEnv()
	if err == nil {
		go writeInfluxDataPoints()
	}
}

func (r *registry) BuildAssetPipeline(ctx context.Context, atype oam.AssetType) (*et.AssetPipeline, error) {
	var stages []pipeline.Stage

	bufsize := 1
	for priority := 1; priority <= 50; priority++ {
		handlers, found := r.handlers[atype][priority]
		if !found || len(handlers) == 0 {
			continue
		}

		id := fmt.Sprintf("%s - Priority: %d", atype, priority)
		task, instances := stageTask(handlers)
		if task == nil {
			continue
		}
		if instances > 1 {
			stages = append(stages, pipeline.DynamicPool(id, task, instances))
			bufsize = max(bufsize, instances)
		} else {
			stages = append(stages, pipeline.FIFO(id, task))
		}
	}

	ap := &et.AssetPipeline{
		Pipeline: pipeline.NewPipeline(stages...),
		Queue:    et.NewPipelineQueue(),
	}

	go func(p *et.AssetPipeline) {
		if err := p.Pipeline.ExecuteBuffered(ctx, p.Queue, makeSink(), bufsize); err != nil {
			r.Log().Error(fmt.Sprintf("Pipeline terminated: %v", err), "OAM type", atype)
		}
	}(ap)

	return ap, nil
}

func makeSink() pipeline.SinkFunc {
	return pipeline.SinkFunc(func(ctx context.Context, data pipeline.Data) error {
		ede, ok := data.(*et.EventDataElement)
		if !ok {
			return errors.New("pipeline sink failed to extract the EventDataElement")
		}
		sendElementOnExit(ede)
		return nil
	})
}

func sendElementOnExit(ede *et.EventDataElement) {
	select {
	case ede.Exit <- ede:
	default:
	}
}

// stageTask returns the task for the handlers at one position of an asset
// type's pipeline, and how many events it may handle at once: the fewest
// instances any of the handlers allows. Handlers sharing a position each
// see every event, together, and the event moves on when all have
// finished. A stage that took one event at a time whenever handlers shared
// a position held every event behind the slowest handler's slowest event.
func stageTask(handlers []*et.Handler) (pipeline.TaskFunc, int) {
	var hs []*et.Handler
	instances := 0
	for _, h := range handlers {
		if h == nil || h.Callback == nil {
			continue
		}

		hs = append(hs, h)
		n := max(h.MaxInstances, 1)
		if instances == 0 || n < instances {
			instances = n
		}
	}

	switch len(hs) {
	case 0:
		return nil, 0
	case 1:
		return handlerTask(hs[0]), instances
	}

	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		ede, err := eventElement(hs[0], data)
		if err != nil {
			return nil, err
		}

		oks := make([]bool, len(hs))
		errs := make([]error, len(hs))
		var wg sync.WaitGroup
		for i, h := range hs {
			wg.Add(1)
			go func() {
				defer wg.Done()
				oks[i], errs[i] = handleElement(ctx, h, ede)
			}()
		}

		wg.Wait()

		// the handlers have finished, so the event's errors are
		// written here alone
		for _, err := range errs {
			if err != nil {
				ede.Error = multierror.Append(ede.Error, err)
			}
		}
		if slices.Contains(oks, false) {
			sendElementOnExit(ede)
			return nil, nil
		}

		return data, nil
	}), instances
}

func handlerTask(h *et.Handler) pipeline.TaskFunc {
	if h == nil || h.Callback == nil {
		return nil
	}

	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		ede, err := eventElement(h, data)
		if err != nil {
			return nil, err
		}

		ok, herr := handleElement(ctx, h, ede)
		if herr != nil {
			ede.Error = multierror.Append(ede.Error, herr)
		}
		if !ok {
			sendElementOnExit(ede)
			return nil, nil
		}

		return data, nil
	})
}

// eventElement returns the event a pipeline task received.
func eventElement(h *et.Handler, data pipeline.Data) (*et.EventDataElement, error) {
	if data == nil {
		return nil, fmt.Errorf("%s pipeline task received a nil data element", h.Name)
	}

	ede, ok := data.(*et.EventDataElement)
	if !ok || ede == nil {
		return nil, fmt.Errorf("%s pipeline task failed to extract the EventDataElement", h.Name)
	}

	return ede, nil
}

// handleElement runs the handler for the event when the configuration's
// transformations call for it. It reports false when the event must leave
// the pipeline (the engine or the session is done), and the handler's
// error.
func handleElement(ctx context.Context, h *et.Handler, ede *et.EventDataElement) (bool, error) {
	select {
	case <-ctx.Done():
		return false, nil
	default:
		if ede.Event.Session.Done() {
			return false, nil
		}
	}

	pname := h.Plugin.Name()
	from := string(ede.Event.Entity.Asset.AssetType())
	transformations := transformationsByType(ede.Event.Session.Config(), from)
	if len(transformations) == 0 || allExcludesPlugin(transformations, pname) {
		return true, nil
	}

	pmatch := tosContainPlugin(transformations, pname)
	if !pmatch {
		if _, err := ede.Event.Session.Config().CheckTransformations(from, h.Transforms...); err == nil {
			pmatch = true
		}
	}
	if !pmatch {
		return true, nil
	}

	start := time.Now()
	err := runHandler(h, ede.Event)
	if influxClient != nil {
		end := time.Now()
		duration := end.Sub(start).Nanoseconds()
		handlerID := fmt.Sprintf("%s-%d", from, h.Position)
		dataPointQueue.Append(influxdb3.NewPointWithMeasurement("handler_duration").
			SetTag("handler", handlerID).SetField("duration", duration).SetTimestamp(end))
	}

	return true, err
}

// runHandler calls a handler, turning a panic into the event's error and
// logging it with its stack: a bug in one plugin must fail that event, not
// stop the engine and every session it runs.
func runHandler(h *et.Handler, e *et.Event) (err error) {
	defer func() {
		if p := recover(); p != nil {
			err = fmt.Errorf("%s handler panicked: %v", h.Name, p)
			if e != nil && e.Session != nil {
				e.Session.Log().Error(err.Error(), "stack", string(debug.Stack()))
			}
		}
	}()

	return h.Callback(e)
}

func transformationsByType(cfg *config.Config, from string) []*config.Transformation {
	var transformations []*config.Transformation

	for _, tf := range cfg.Transformations {
		if strings.EqualFold(tf.From, from) {
			transformations = append(transformations, tf)
		}
	}

	return transformations
}

func tosContainPlugin(transformations []*config.Transformation, pname string) bool {
	for _, tf := range transformations {
		if strings.EqualFold(tf.To, pname) {
			return true
		}
	}
	return false
}

func allExcludesPlugin(transformations []*config.Transformation, pname string) bool {
	var all *config.Transformation

	for _, tf := range transformations {
		if strings.EqualFold(tf.To, "all") {
			all = tf
			break
		}
	}

	if all == nil {
		return false
	}

	for _, ex := range all.Exclude {
		if strings.EqualFold(ex, pname) {
			return true
		}
	}
	return false
}

func writeInfluxDataPoints() {
	t := time.NewTicker(5 * time.Second)
	defer t.Stop()

	write := func() {
		var points []*influxdb3.Point

		dataPointQueue.Process(func(item interface{}) {
			if p, valid := item.(*influxdb3.Point); valid {
				points = append(points, p)
			}
		})

		if len(points) > 0 {
			_ = influxClient.WritePoints(context.Background(), points)
		}
	}

	for {
		select {
		case <-t.C:
			write()
		case <-dataPointQueue.Signal():
			if dataPointQueue.Len() >= 100 {
				write()
			}
		}
	}
}
