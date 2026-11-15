// Copyright © by Jeff Foley 2017-2026. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package cli

import "github.com/owasp-amass/amass/v5/internal/lens"

// useVulnData points the vulnerable lens at path when one was given.
func useVulnData(path string) {
	if path != "" {
		lens.VulnDataPath = func() string { return path }
	}
}
