// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package resources

import (
	"fmt"
	"testing"
)

func TestGetIP2ASNData(t *testing.T) {
	_, err := GetIP2ASNData()
	if fmt.Sprintf("%v", err) != "<nil>" {
		t.Errorf("parseIPs.parseRange() error = %v, wantErr <nil>", err)

	}
}
func TestGetDefaultScripts(t *testing.T) {
	_, err := GetDefaultScripts()
	if fmt.Sprintf("%v", err) != "<nil>" {
		t.Errorf("parseIPs.parseRange() error = %v, wantErr <nil>", err)

	}
}
