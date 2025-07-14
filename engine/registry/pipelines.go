// Copyright © by Jeff Foley 2017-2025. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package registry

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/caffix/pipeline"
	multierror "github.com/hashicorp/go-multierror"
	"github.com/owasp-amass/amass/v5/config"
	et "github.com/owasp-amass/amass/v5/engine/types"
)

func (r *registry) BuildPipelines() error {
	r.Lock()
	defer r.Unlock()

	for k := range r.handlers {
		p, err := r.buildAssetPipeline(string(k))
		if err != nil {
			return err
		}
		r.pipelines[k] = p
	}
	return nil
}

func (r *registry) buildAssetPipeline(atype string) (*et.AssetPipeline, error) {
	var stages []pipeline.Stage

	bufsize := 1
	for priority := 1; priority <= 9; priority++ {
		handlers, found := r.handlers[atype][priority]
		if !found || len(handlers) == 0 {
			continue
		}

		id := fmt.Sprintf("%s - Priority: %d", atype, priority)
		if len(handlers) == 1 {
			h := handlers[0]

			if max := h.MaxInstances; max > 0 {
				stages = append(stages, pipeline.FixedPool(id, handlerTask(h), max))
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
		if err := p.Pipeline.ExecuteBuffered(context.TODO(), p.Queue, makeSink(), bufsize); err != nil {
			r.logger.Error(fmt.Sprintf("Pipeline terminated: %v", err), "OAM type", atype)
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

		ede.Queue <- ede
		return nil
	})
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
			ede.Queue <- ede
			return nil, nil
		default:
			if ede.Event.Session.Done() {
				ede.Queue <- ede
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
				if err := r.Callback(ede.Event); err != nil {
					ede.Error = multierror.Append(ede.Error, err)
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
