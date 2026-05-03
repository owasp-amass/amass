// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"
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
		if len(handlers) == 1 {
			h := handlers[0]

			if max := h.MaxInstances; max > 1 {
				stages = append(stages, pipeline.DynamicPool(id, handlerTask(h), max))
				if max > bufsize {
					bufsize = max
				}
			} else {
				stages = append(stages, pipeline.FIFO(id, handlerTask(h)))
			}
		} else {
			var tasks []pipeline.Task

			for _, handler := range handlers {
				if h := handlerTask(handler); h != nil {
					tasks = append(tasks, h)
				}
			}

			stages = append(stages, pipeline.Parallel(id, tasks...))
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

func handlerTask(h *et.Handler) pipeline.TaskFunc {
	if h == nil || h.Callback == nil {
		return nil
	}

	r := h
	return pipeline.TaskFunc(func(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
		if data == nil {
			return nil, fmt.Errorf("%s pipeline task received a nil data element", h.Name)
		}

		ede, ok := data.(*et.EventDataElement)
		if !ok || ede == nil {
			return nil, fmt.Errorf("%s pipeline task failed to extract the EventDataElement", h.Name)
		}

		select {
		case <-ctx.Done():
			sendElementOnExit(ede)
			return nil, nil
		default:
			if ede.Event.Session.Done() {
				sendElementOnExit(ede)
				return nil, nil
			}
		}

		pname := h.Plugin.Name()
		from := string(ede.Event.Entity.Asset.AssetType())
		transformations := transformationsByType(ede.Event.Session.Config(), from)
		if len(transformations) > 0 && !allExcludesPlugin(transformations, pname) {
			pmatch := tosContainPlugin(transformations, pname)

			if !pmatch {
				if _, err := ede.Event.Session.Config().CheckTransformations(from, h.Transforms...); err == nil {
					pmatch = true
				}
			}
			if pmatch {
				start := time.Now()
				if err := r.Callback(ede.Event); err != nil {
					ede.Error = multierror.Append(ede.Error, err)
				}
				if influxClient != nil {
					end := time.Now()
					duration := end.Sub(start).Nanoseconds()
					handlerID := fmt.Sprintf("%s-%d", from, h.Position)
					dataPointQueue.Append(influxdb3.NewPointWithMeasurement("handler_duration").
						SetTag("handler", handlerID).SetField("duration", duration).SetTimestamp(end))
				}
			}
		}
		return data, nil
	})
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
