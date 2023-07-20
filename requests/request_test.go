// Copyright © by Jeff Foley 2017-2023. All rights reserved.
// Use of this source code is governed by Apache 2 LICENSE that can be found in the LICENSE file.
// SPDX-License-Identifier: Apache-2.0

package requests

import (
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestDNSRequestClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  DNSRequest
	}{
		{
			name: "Simple test",
			req: DNSRequest{
				Name:    "test",
				Domain:  "www.example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := test.req.Clone().(*DNSRequest)
			require.Equal(t, clone.Name, test.req.Name)
			require.Equal(t, clone.Domain, test.req.Domain)
			require.Equal(t, clone.Records, test.req.Records)
		})
	}

}

func TestDNSRequestValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     DNSRequest
		success bool
	}{
		{
			name: "Invalid test",
			req: DNSRequest{
				Name:    "test",
				Domain:  "www.example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
			success: false,
		},
		{
			name: "Valid test",
			req: DNSRequest{
				Name:    "example.com",
				Domain:  "example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
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

func TestResolvedRequestClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  ResolvedRequest
	}{
		{
			name: "Simple test",
			req: ResolvedRequest{
				Name:    "test",
				Domain:  "www.example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := test.req.Clone().(*ResolvedRequest)
			require.Equal(t, clone.Name, test.req.Name)
			require.Equal(t, clone.Domain, test.req.Domain)
			require.Equal(t, clone.Records, test.req.Records)
		})
	}
}

func TestResolvedRequestValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     ResolvedRequest
		success bool
	}{
		{
			name: "Invalid test",
			req: ResolvedRequest{
				Name:    "test",
				Domain:  "www.example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
			success: false,
		},
		{
			name: "Valid test",
			req: ResolvedRequest{
				Name:    "example.com",
				Domain:  "example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
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

func TestSubdomainRequestClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  SubdomainRequest
	}{
		{
			name: "Simple test",
			req: SubdomainRequest{
				Name:    "test",
				Domain:  "www.example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := test.req.Clone().(*SubdomainRequest)
			require.Equal(t, clone.Name, test.req.Name)
			require.Equal(t, clone.Domain, test.req.Domain)
			require.Equal(t, clone.Records, test.req.Records)
		})
	}
}

func TestSubdomainRequestValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     SubdomainRequest
		success bool
	}{
		{
			name: "Invalid test",
			req: SubdomainRequest{
				Name:    "test",
				Domain:  "www.example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
				Times:   0,
			},
			success: false,
		},
		{
			name: "Valid test",
			req: SubdomainRequest{
				Name:    "example.com",
				Domain:  "example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
				Times:   3,
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

func TestZoneXFRRequestClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  ZoneXFRRequest
	}{
		{
			name: "Simple test",
			req: ZoneXFRRequest{
				Name:   "test",
				Domain: "www.example.com",
				Server: "test",
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := test.req.Clone().(*ZoneXFRRequest)
			require.Equal(t, clone.Name, test.req.Name)
			require.Equal(t, clone.Domain, test.req.Domain)
			require.Equal(t, clone.Server, test.req.Server)
		})
	}
}

func TestAddrRequestClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  AddrRequest
	}{
		{
			name: "Simple test",
			req: AddrRequest{
				Address: "8.8.8.8",
				Domain:  "www.example.com",
				InScope: true,
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := test.req.Clone().(*AddrRequest)
			require.Equal(t, clone.Address, test.req.Address)
			require.Equal(t, clone.Domain, test.req.Domain)
			require.Equal(t, clone.InScope, test.req.InScope)
		})
	}
}

func TestAddrRequestValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     AddrRequest
		success bool
	}{
		{
			name: "Invalid test",
			req: AddrRequest{
				Address: "NotAnIP",
				Domain:  "www.example.com",
				InScope: false,
			},
			success: false,
		},
		{
			name: "Valid test",
			req: AddrRequest{
				Address: "8.8.8.8",
				Domain:  "example.com",
				InScope: true,
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

func TestSanitizeDNSRequest(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  DNSRequest
	}{
		{
			name: "Simple test",
			req: DNSRequest{
				Name:    "   Example.com   ",
				Domain:  "                    Example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
		},
		{
			name: "RemoveAsteriksTest",
			req: DNSRequest{
				Name:    "*.Example.com",
				Domain:  "Example.com",
				Records: append([]DNSAnswer(nil), []DNSAnswer{}...),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SanitizeDNSRequest(&test.req)
			require.Equal(t, "example.com", test.req.Name)
			require.Equal(t, "example.com", test.req.Domain)
		})
	}

}

func TestASNRequestClone(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		req  ASNRequest
	}{
		{
			name: "Simple test",
			req: ASNRequest{
				Address:        "8.8.8.8",
				ASN:            11111,
				Prefix:         "",
				CC:             "",
				Registry:       "",
				AllocationDate: time.Now(),
				Description:    "",
				Netblocks:      []string{},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			clone := test.req.Clone().(*ASNRequest)
			require.Equal(t, clone.Address, test.req.Address)
			require.Equal(t, clone.ASN, test.req.ASN)
			require.Equal(t, clone.Prefix, test.req.Prefix)
			require.Equal(t, clone.CC, test.req.CC)
			require.Equal(t, clone.Registry, test.req.Registry)
			require.Equal(t, clone.AllocationDate, test.req.AllocationDate)
			require.Equal(t, clone.Description, test.req.Description)
			require.Equal(t, clone.Netblocks, test.req.Netblocks)
		})
	}

}

func TestASNRequestValid(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		req     ASNRequest
		success bool
	}{
		{
			name: "Valid test",
			req: ASNRequest{
				Address:        "8.8.8.8",
				ASN:            11111,
				Prefix:         "8.8.8.8/8",
				CC:             "",
				Registry:       "",
				AllocationDate: time.Now(),
				Description:    "",
				Netblocks:      []string{},
			},
			success: true,
		},
		{
			name: "Invalid test - Empty Prefix",
			req: ASNRequest{
				Address:        "8.8.8.8",
				ASN:            11111,
				Prefix:         "",
				CC:             "",
				Registry:       "",
				AllocationDate: time.Now(),
				Description:    "",
				Netblocks:      []string{},
			},
			success: false,
		},
		{
			name: "Invalid test - Malformed Address",
			req: ASNRequest{
				Address:        "300.300.300.300",
				ASN:            11111,
				Prefix:         "8.8.8.8/8",
				CC:             "",
				Registry:       "",
				AllocationDate: time.Now(),
				Description:    "",
				Netblocks:      []string{},
			},
			success: false,
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
