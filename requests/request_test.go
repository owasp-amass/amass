// Copyright 2017 Jeff Foley. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.

package requests

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTrustedTag(t *testing.T) {
	tests := []struct {
		Value    string
		Expected bool
	}{
		{NONE, false},
		{ALT, false},
		{GUESS, false},
		{ARCHIVE, true},
		{API, false},
		{AXFR, true},
		{BRUTE, false},
		{CERT, true},
		{DNS, true},
		{EXTERNAL, false},
		{SCRAPE, false},
	}

	for _, test := range tests {
		if r := TrustedTag(test.Value); r != test.Expected {
			t.Errorf("%s returned %t instead of %t", test.Value, r, test.Expected)
		}
	}
}

func TestDNSRequestClone(t *testing.T) {
    t.Parallel()
    tests := []struct{
        name        string
        req         DNSRequest
    }{
        {
            name: "Simple test",
            req:  DNSRequest{
                Name: "test",
                Domain: "www.example.com",
                Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
                Tag:    "test",
                Source: "test",
            },
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T) {
            clone := test.req.Clone().(*DNSRequest)
            require.Equal(t, clone.Name, test.req.Name)
            require.Equal(t, clone.Domain, test.req.Domain)
            require.Equal(t, clone.Records, test.req.Records)
            require.Equal(t, clone.Tag, test.req.Tag)
            require.Equal(t, clone.Source, test.req.Source)
        })
    }

}

func TestDNSRequestValid(t *testing.T) {
    tests := []struct{
        name        string
        req         DNSRequest
        success     bool
    }{
        {
            name: "Invalid test",
            req:  DNSRequest{
                Name: "test",
                Domain: "www.example.com",
                Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
                Tag:    "test",
                Source: "test",
            },
            success: false,
        },
        {
            name: "Valid test",
            req:  DNSRequest{
                Name: "example.com",
                Domain: "www.example.com",
                Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
                Tag:    "test",
                Source: "test",
            },
            success: true,
        },
    }
    for _, test := range tests {
        t.Run(test.name, func(t *testing.T) {
            if test.success {
                valid := test.req.Valid()
                require.True(t, valid)
            } else {
                valid := test.req.Valid()
                require.False(t, valid)
            }
        })
    }
}
