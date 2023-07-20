// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package systems

import (
	"reflect"
	"testing"
)

func TestCheckAddresses(t *testing.T) {
	tests := []struct {
		name     string
		addr     []string
		expected []string
	}{
		{
			name:     "IP without port",
			addr:     []string{"1.1.1.1"},
			expected: []string{"1.1.1.1:53"},
		},
		{
			name:     "IP with port already set",
			addr:     []string{"1.1.1.1:58"},
			expected: []string{"1.1.1.1:58"},
		},
		{
			name:     "Multiple IPs",
			addr:     []string{"1.1.1.1", "8.8.8.8:80", "111.111.111.111"},
			expected: []string{"1.1.1.1:53", "8.8.8.8:80", "111.111.111.111:53"},
		},
		{
			name:     "Invalid IP",
			addr:     []string{"NotAnIP"},
			expected: []string{},
		},
		{
			name:     "Invalid IP with Port",
			addr:     []string{"300.300.300.300:53"},
			expected: []string{},
		},
		{
			name:     "Multiple IPs, valid and invalid",
			addr:     []string{"192.168.61.221", "NotAnIP:80", "111.111.111.111:111"},
			expected: []string{"192.168.61.221:53", "111.111.111.111:111"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ips := checkAddresses(tt.addr)
			if !reflect.DeepEqual(ips, tt.expected) {
				t.Errorf("Unexpected Result, expected %v, got %v", tt.expected, ips)
			}
		})
	}
}
