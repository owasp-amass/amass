// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"testing"
	"time"

	"github.com/OWASP/Amass/v3/requests"
)

func TestCachedResponse(t *testing.T) {
	script, sys := setupMockScriptEnv(`
		name="cache"
		type="testing"

		function vertical(ctx, domain)
			cache_response(ctx, "https://www.owasp.org", "success.owasp.org")

			local _, body, status, err = request(ctx, {['url']="https://www.owasp.org"})
			if (err == nil and status == 200 and body ~= "") then
				new_name(ctx, body)
    		end
		end
	`)
	if script == nil || sys == nil {
		t.Fatal("Failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	sys.Config().MinimumTTL = 1440
	dsc := sys.Config().GetDataSourceConfig(script.String())
	dsc.TTL = 1440

	sys.Config().AddDomain("owasp.org")
	script.Input() <- &requests.DNSRequest{Domain: "owasp.org"}

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()

	select {
	case <-timer.C:
		t.Error("The test timed out")
	case req := <-script.Output():
		if ans, ok := req.(*requests.DNSRequest); !ok || ans.Name != "success.owasp.org" {
			t.Error("Cache process failed")
		}
	}
}
