// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package amass

import (
	"testing"
	"time"
)

func TestNetblockService(t *testing.T) {
	in := make(chan *AmassRequest)
	out := make(chan *AmassRequest)
	config := DefaultConfig()
	config.Setup()

	srv := NewNetblockService(in, out, config)

	srv.Start()
	in <- &AmassRequest{Address: "104.244.42.65"}

	quit := time.NewTimer(5 * time.Second)
	defer quit.Stop()

	select {
	case req := <-out:
		if req.Netblock.String() != "104.244.42.0/24" {
			t.Errorf("Address %s instead belongs in netblock %s\n", req.Address, req.Netblock.String())
		}
	case <-quit.C:
		t.Error("The request timed out")
	}

	srv.Stop()
}
