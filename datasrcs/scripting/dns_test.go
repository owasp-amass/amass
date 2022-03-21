// Copyright © by Jeff Foley 2021-2022. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package scripting

import (
	"testing"
	"time"

	"github.com/OWASP/Amass/v3/requests"
)

func TestResolve(t *testing.T) {
	expected := []string{"www.owasp.org", "owasp.org", "owasp.org", "owasp.org", "owasp.org"}
	script, sys := setupMockScriptEnv(`
		name="resolve"
		type="testing"

		function vertical(ctx, domain)
			local tests = {
				{"", "A"},
				{"www.owasp.org", ""},
				{"www.owasp.org", "AAAA"},
				{"www.owasp.org", "PTR"},
				{"www.utica.edu", "A"},
				{"bestsecurity.owasp.org", "A"},
				{"owasp.org", "NS"},
				{"owasp.org", "MX"},
				{"owasp.org", "TXT"},
				{"owasp.org", "SOA"},
			}

			for _, t in ipairs(tests) do
				local resp, err = resolve(ctx, t[1], t[2])
				if (err == nil and #resp > 0) then
					new_name(ctx, resp[1].rrname)
				end
    		end
		end
	`)
	if script == nil || sys == nil {
		t.Fatal("Failed to initialize the scripting environment")
	}
	defer func() { _ = sys.Shutdown() }()

	sys.Config().AddDomain("owasp.org")
	script.Input() <- &requests.DNSRequest{Domain: "owasp.org"}

	timer := time.NewTimer(15 * time.Second)
	defer timer.Stop()
loop:
	for _, name := range expected {
		select {
		case <-timer.C:
			t.Error("The test timed out")
			break loop
		case req := <-script.Output():
			if ans, ok := req.(*requests.DNSRequest); !ok || ans.Name != name {
				t.Error("Failed")
			}
		}
	}
}
