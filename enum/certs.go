package enum

import (
	"context"
	"github.com/OWASP/Amass/v3/net/http"
	"github.com/OWASP/Amass/v3/requests"
	"github.com/caffix/pipeline"
	"github.com/caffix/queue"
	"strings"
)

// certsTask is the task that handles all requests related to ssl extraction within the pipeline.
type certsTask struct {
	enum      *Enumeration
	queue     queue.Queue
	tokenPool chan struct{}
}

type certsTaskArgs struct {
	Ctx    context.Context
	Data   pipeline.Data
	Params pipeline.TaskParams
}

// newCertsTask returns a certsTask specific to the provided Enumeration.
func newCertsTask(e *Enumeration, max int) *certsTask {
	if max <= 0 {
		return nil
	}

	tokenPool := make(chan struct{}, max)
	for i := 0; i < max; i++ {
		tokenPool <- struct{}{}
	}

	a := &certsTask{
		enum:      e,
		queue:     queue.NewQueue(),
		tokenPool: tokenPool,
	}

	go a.ProcessQueue()
	return a
}

func (c *certsTask) Stop() {
	c.queue.Process(func(e interface{}) {})
}

func (c *certsTask) ProcessQueue() {
	for {
		select {
		case <-c.enum.done:
			return
		case <-c.queue.Signal():
			c.processTask()
		}
	}
}

// Process implements the pipeline Task interface.
func (c *certsTask) Process(ctx context.Context, data pipeline.Data, tp pipeline.TaskParams) (pipeline.Data, error) {
	select {
	case <-ctx.Done():
		return nil, nil
	default:
	}

	var ok bool
	switch data.(type) {
	case *requests.AddrRequest:
		ok = true
	}

	if ok {
		c.queue.Append(&certsTaskArgs{
			Ctx:    ctx,
			Data:   data.Clone(),
			Params: tp,
		})
	}

	return data, nil
}

func (c *certsTask) processTask() {
	select {
	case <-c.enum.ctx.Done():
		return
	case <-c.enum.done:
		return
	case <-c.tokenPool:
		element, ok := c.queue.Next()
		if !ok {
			c.tokenPool <- struct{}{}
			return
		}

		args := element.(*certsTaskArgs)
		switch v := args.Data.(type) {
		case *requests.AddrRequest:
			if v.InScope {
				go c.certEnumeration(args.Ctx, v, args.Params)
			}
		}
	}
}

func (c *certsTask) certEnumeration(ctx context.Context, req *requests.AddrRequest, tp pipeline.TaskParams) {
	defer func() { c.tokenPool <- struct{}{} }()

	if req == nil || !req.Valid() {
		return
	}

	for _, name := range http.PullCertificateNames(ctx, req.Address, c.enum.Config.Ports) {
		select {
		case <-ctx.Done():
			return
		default:
		}

		if n := strings.TrimSpace(name); n != "" {
			if domain := c.enum.Config.WhichDomain(n); domain != "" {
				pipeline.SendData(ctx, "new", &requests.DNSRequest{
					Name:   n,
					Domain: domain,
					Tag:    requests.CERT,
					Source: "Active Cert",
				}, tp)
			}
		}
	}
}
